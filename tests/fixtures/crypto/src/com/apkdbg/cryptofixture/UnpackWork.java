package com.apkdbg.cryptofixture;

import android.content.Context;
import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.security.MessageDigest;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import dalvik.system.InMemoryDexClassLoader;

/**
 * Runtime DEX payload fixture for apkdbg unpack discovery validation (#28).
 * Handles com.apkdbg.cryptofixture.UNPACK: decrypts the embedded payload
 * DEX (assets/encrypted_dex.bin, AES-128-CBC, fixed key committed in
 * build.sh) via Cipher.doFinal, then exercises every declared corpus case
 * through the supported boundaries. Ground truth is logged to logcat under
 * tag CryptoFixture:
 *
 *   UNPACK payload.len=<n> payload.sha256=<hex>
 *   UNPACK case=<name> expected=<outcome> loaded=<true|false>
 *   UNPACK ok
 *
 * Cases: heap_single (validated), heap_array (validated, duplicate of
 * heap_single), heap_duplicate (validated, duplicate), fake_magic
 * (invalid), non_dex (not_dex), empty (empty), direct (unsupported —
 * capability result; the loader itself accepts direct buffers natively).
 */
public class UnpackWork {
    private static final String TAG = "CryptoFixture";
    // fixed key/iv: must match the build.sh encryption step
    static final byte[] PAYLOAD_KEY =
            RunReceiver.hex("a1b2c3d4e5f60718293a4b5c6d7e8f90");
    static final byte[] PAYLOAD_IV =
            RunReceiver.hex("0f1e2d3c4b5a69788796a5b4c3d2e1f0");

    public static void run(Context app) {
        try {
            byte[] plain = decrypt(app, readAsset(app));
            String sha = RunReceiver.hex(
                    MessageDigest.getInstance("SHA-256").digest(plain));
            Log.i(TAG, "UNPACK payload.len=" + plain.length
                    + " payload.sha256=" + sha);

            load("heap_single", "validated",
                    ByteBuffer.wrap(plain), false);
            load("heap_array", "validated_duplicate",
                    ByteBuffer.wrap(plain), true);
            load("heap_duplicate", "validated_duplicate",
                    ByteBuffer.wrap(plain), false);

            byte[] fake = new byte[256];
            byte[] magic = "dex\n035\0".getBytes("UTF-8");
            System.arraycopy(magic, 0, fake, 0, magic.length);
            for (int i = magic.length; i < fake.length; i++) {
                fake[i] = 0x41;
            }
            load("fake_magic", "invalid", ByteBuffer.wrap(fake), false);

            load("non_dex", "not_dex",
                    ByteBuffer.wrap("an ordinary non-DEX buffer".getBytes("UTF-8")),
                    false);
            load("empty", "empty", ByteBuffer.allocate(0), false);

            ByteBuffer direct = ByteBuffer.allocateDirect(plain.length);
            direct.put(plain);
            direct.flip();
            load("direct", "unsupported", direct, false);

            Log.i(TAG, "UNPACK ok");
        } catch (Exception e) {
            Log.e(TAG, "UNPACK failed", e);
        }
    }

    private static void load(String name, String expected, ByteBuffer buf,
                             boolean asArray) {
        boolean loaded = false;
        String err = null;
        try {
            ClassLoader parent = UnpackWork.class.getClassLoader();
            InMemoryDexClassLoader cl = asArray
                    ? new InMemoryDexClassLoader(new ByteBuffer[]{buf}, parent)
                    : new InMemoryDexClassLoader(buf, parent);
            loaded = cl.loadClass(
                    "com.apkdbg.cryptofixture.payload.Payload") != null;
        } catch (Throwable t) {  // invalid/empty/non-dex cases throw here
            err = t.getClass().getSimpleName();
        }
        Log.i(TAG, "UNPACK case=" + name + " expected=" + expected
                + " loaded=" + loaded
                + (err != null ? " err=" + err : ""));
    }

    private static byte[] readAsset(Context app) throws Exception {
        InputStream in = app.getAssets().open("encrypted_dex.bin");
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] tmp = new byte[4096];
        int n;
        while ((n = in.read(tmp)) != -1) {
            out.write(tmp, 0, n);
        }
        in.close();
        return out.toByteArray();
    }

    private static byte[] decrypt(Context app, byte[] blob) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE,
                new SecretKeySpec(PAYLOAD_KEY, "AES"),
                new IvParameterSpec(PAYLOAD_IV));
        return cipher.doFinal(blob);
    }
}
