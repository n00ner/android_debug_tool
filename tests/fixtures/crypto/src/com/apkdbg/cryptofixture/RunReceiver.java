package com.apkdbg.cryptofixture;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

import java.security.MessageDigest;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Deterministic crypto fixture for apkdbg hook_crypto validation (#21).
 * Handles com.apkdbg.cryptofixture.RUN; every receive executes the NIST
 * SP 800-38A F.2.1 AES-128-CBC vector plus HMAC-SHA256 / SHA-256 over the
 * same block, logging inputs and outputs as ground truth.
 */
public class RunReceiver extends BroadcastReceiver {
    public static final String ACTION_RUN = "com.apkdbg.cryptofixture.RUN";
    public static final String ACTION_RUN_STRINGS =
            "com.apkdbg.cryptofixture.STRINGS";
    public static final String ACTION_BENCH = "com.apkdbg.cryptofixture.BENCH";
    public static final String ACTION_FW_STORE =
            "com.apkdbg.cryptofixture.FW_STORE";
    public static final String ACTION_FW_SVC =
            "com.apkdbg.cryptofixture.FW_SVC";
    public static final String ACTION_FW_BENCH =
            "com.apkdbg.cryptofixture.FW_BENCH";
    private static final String TAG = "CryptoFixture";

    static final byte[] AES_KEY = hex("2b7e151628aed2a6abf7158809cf4f3c");
    static final byte[] IV = hex("000102030405060708090a0b0c0d0e0f");
    static final byte[] MSG = hex("6bc1bee22e409f96e93d7e117393172a");

    @Override
    public void onReceive(Context ctx, Intent intent) {
        if (intent == null) {
            return;
        }
        if (ACTION_RUN_STRINGS.equals(intent.getAction())) {
            StringWork.runAll();   // string-watcher fixture paths (#26)
            return;
        }
        if (ACTION_BENCH.equals(intent.getAction())) {
            int iters = intent.getIntExtra("iters", 200000);
            long acc = StringWork.hotLoop(iters);
            Log.i(TAG, "BENCH iters=" + iters + " acc=" + acc);
            return;
        }
        if (ACTION_FW_STORE.equals(intent.getAction())
                || ACTION_FW_SVC.equals(intent.getAction())
                || ACTION_FW_BENCH.equals(intent.getAction())) {
            // the receiver context is a ReceiverRestrictedContext (it
            // disallows getSharedPreferences); the application context is
            // the real ContextImpl and exercises the same watched paths
            Context app = ctx.getApplicationContext();
            if (ACTION_FW_STORE.equals(intent.getAction())) {
                FrameworkWork.storagePaths(app);
                FrameworkWork.customEditorPaths();
            } else if (ACTION_FW_SVC.equals(intent.getAction())) {
                FrameworkWork.servicePaths(app);
            } else {
                int iters = intent.getIntExtra("iters", 50000);
                long acc = FrameworkWork.benchLoop(app, iters);
                Log.i(TAG, "FWBENCH iters=" + iters + " acc=" + acc);
            }
            return;
        }
        if (!ACTION_RUN.equals(intent.getAction())) {
            return;
        }
        try {
            SecretKeySpec key = new SecretKeySpec(AES_KEY, "AES");
            IvParameterSpec iv = new IvParameterSpec(IV);
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key);      // exercises init(int,Key)
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);  // re-init with fixed IV
            byte[] ct = cipher.doFinal(MSG);
            Log.i(TAG, "cipher.input=" + hex(MSG));
            Log.i(TAG, "cipher.output=" + hex(ct));

            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(key);
            byte[] tag = mac.doFinal(MSG);
            Log.i(TAG, "mac.input=" + hex(MSG));
            Log.i(TAG, "mac.output=" + hex(tag));

            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(MSG);
            Log.i(TAG, "digest.input=" + hex(MSG));
            Log.i(TAG, "digest.output=" + hex(digest));
            Log.i(TAG, "RUN ok");
        } catch (Exception e) {
            Log.e(TAG, "RUN failed", e);
        }
    }

    static byte[] hex(String s) {
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        }
        return out;
    }

    static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) {
            sb.append(Character.forDigit((x >> 4) & 0xF, 16));
            sb.append(Character.forDigit(x & 0xF, 16));
        }
        return sb.toString();
    }
}
