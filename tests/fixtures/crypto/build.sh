#!/usr/bin/env bash
# Rebuild crypto_fixture.apk from source (Windows Git Bash).
# Tools: Zulu JDK 21 javac/keytool/java, Android SDK build-tools 30.0.3
# (d8.jar / aapt2.exe / zipalign.exe / apksigner.jar; the .bat wrappers need
# tools/lib/find_java.bat which bare build-tools lacks, so jars are invoked
# directly), platform android.jar (android-30: newer jars' resources.arsc
# is too new for aapt2 30.0.3).
set -euo pipefail
cd "$(dirname "$0")"

JAVA_HOME="/c/Program Files/Zulu/zulu-21"
JAVA="$JAVA_HOME/bin/java"
JAVAC="$JAVA_HOME/bin/javac"
KEYTOOL="$JAVA_HOME/bin/keytool"
SDK="/c/Users/streit/AppData/Local/Android/Sdk"
BT="$SDK/build-tools/30.0.3"
ANDROID_JAR="$SDK/platforms/android-30/android.jar"

rm -rf out && mkdir -p out/classes out/dex out/payload_classes out/payload_dex

"$JAVAC" -source 8 -target 8 -classpath "$ANDROID_JAR" \
    -d out/classes src/com/apkdbg/cryptofixture/*.java

"$JAVA" -cp "$BT/lib/d8.jar" com.android.tools.r8.D8 \
    --min-api 24 --lib "$ANDROID_JAR" \
    --output out/dex out/classes/com/apkdbg/cryptofixture/*.class

# --- issue #28: payload DEX -> AES-encrypted asset --------------------------
# A tiny class compiled to a standalone DEX, encrypted with a fixed
# AES-128-CBC key/iv (must match UnpackWork.PAYLOAD_KEY/PAYLOAD_IV), and
# committed as assets/encrypted_dex.bin. Ground truth is derivable
# host-side: `python _aes.py` self-test plus cbc_decrypt of the asset.
"$JAVAC" -source 8 -target 8 -classpath "$ANDROID_JAR" \
    -d out/payload_classes src/com/apkdbg/cryptofixture/payload/*.java

"$JAVA" -cp "$BT/lib/d8.jar" com.android.tools.r8.D8 \
    --min-api 26 --lib "$ANDROID_JAR" \
    --output out/payload_dex \
    out/payload_classes/com/apkdbg/cryptofixture/payload/*.class

mkdir -p assets
python - <<'EOF'
import hashlib
import json
import sys

sys.path.insert(0, ".")
from _aes import cbc_encrypt

KEY = bytes.fromhex("a1b2c3d4e5f60718293a4b5c6d7e8f90")
IV = bytes.fromhex("0f1e2d3c4b5a69788796a5b4c3d2e1f0")
plain = open("out/payload_dex/classes.dex", "rb").read()
with open("assets/encrypted_dex.bin", "wb") as fh:
    fh.write(cbc_encrypt(KEY, IV, plain))
truth = {"asset": "encrypted_dex.bin", "key_hex": KEY.hex(),
         "iv_hex": IV.hex(), "plaintext_len": len(plain),
         "plaintext_sha256": hashlib.sha256(plain).hexdigest()}
with open("payload_ground_truth.json", "w") as fh:
    json.dump(truth, fh, indent=1)
    fh.write("\n")
print("payload dex:", len(plain), "bytes sha256", truth["plaintext_sha256"])
EOF

"$BT/aapt2.exe" link -o out/unsigned.apk -I "$ANDROID_JAR" \
    --manifest AndroidManifest.xml -A assets \
    --min-sdk-version 24 --target-sdk-version 35

python - <<'EOF'
import zipfile
with zipfile.ZipFile("out/unsigned.apk", "a", zipfile.ZIP_DEFLATED) as z:
    z.write("out/dex/classes.dex", "classes.dex")
EOF

"$BT/zipalign.exe" -f 4 out/unsigned.apk out/aligned.apk

if [ ! -f out/debug.keystore ]; then
    "$KEYTOOL" -genkeypair -keystore out/debug.keystore -alias androiddebugkey \
        -keyalg RSA -keysize 2048 -validity 10000 \
        -storepass android -keypass android -dname "CN=Android Debug"
fi

"$JAVA" -cp "$BT/lib/apksigner.jar" com.android.apksigner.ApkSignerTool sign \
    --ks out/debug.keystore --ks-pass pass:android --key-pass pass:android \
    --out crypto_fixture.apk out/aligned.apk
"$JAVA" -cp "$BT/lib/apksigner.jar" com.android.apksigner.ApkSignerTool verify \
    crypto_fixture.apk
ls -l crypto_fixture.apk
