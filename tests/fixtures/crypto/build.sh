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

rm -rf out && mkdir -p out/classes out/dex

"$JAVAC" -source 8 -target 8 -classpath "$ANDROID_JAR" \
    -d out/classes src/com/apkdbg/cryptofixture/RunReceiver.java

"$JAVA" -cp "$BT/lib/d8.jar" com.android.tools.r8.D8 \
    --min-api 24 --lib "$ANDROID_JAR" \
    --output out/dex out/classes/com/apkdbg/cryptofixture/*.class

"$BT/aapt2.exe" link -o out/unsigned.apk -I "$ANDROID_JAR" \
    --manifest AndroidManifest.xml \
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
