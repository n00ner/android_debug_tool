package com.apkdbg.cryptofixture;

import android.util.Log;

import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;

/**
 * String-watcher fixture for apkdbg watch_strings validation (#26).
 *
 * runAll() exercises:
 *   (a) decryptUrl(): a selected decryptor method returning an encrypted
 *       test URL — the producer-return observation point (custom profile
 *       {"cls":"Lcom/apkdbg/cryptofixture/StringWork;","method":"decryptUrl",
 *        "sig":"()Ljava/lang/String;"});
 *   (b) viaBuilder(): a StringBuilder-built string — observed by the
 *       stringbuilder.tostring profile;
 *   (c) viaNewString() / viaReflection(): strings constructed WITHOUT
 *       StringBuilder (constructor + reflective paths) — the StringBuilder
 *       observation point must NOT capture these; they are the documented
 *       bypass paths, proving observation points are not full coverage.
 *
 * hotLoop(int) is the benchmark workload: repeated StringBuilder usage so
 * the harness can measure event rate and slowdown for disabled /
 * best_effort / attributed capture.
 */
public class StringWork {
    private static final String TAG = "CryptoFixture";
    private static final byte XOR_KEY = 0x5A;
    // "https://fixture.example/decrypted-url" XOR 0x5A
    private static final byte[] ENC_URL = {
        50, 46, 46, 42, 41, 96, 117, 117, 60, 51, 34, 46, 47, 40, 63, 116,
        63, 34, 59, 55, 42, 54, 63, 117, 62, 63, 57, 40, 35, 42, 46, 63,
        62, 119, 47, 40, 54
    };

    public static String decryptUrl() {
        byte[] out = new byte[ENC_URL.length];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) (ENC_URL[i] ^ XOR_KEY);
        }
        return new String(out, StandardCharsets.UTF_8);
    }

    public static String viaBuilder(String a, String b) {
        StringBuilder sb = new StringBuilder();
        sb.append(a).append(b);
        return sb.toString();
    }

    public static String viaNewString() {
        // "ctor-built-secret" — no StringBuilder anywhere on this path
        byte[] raw = {
            99, 116, 111, 114, 45, 98, 117, 105, 108, 116, 45, 115, 101,
            99, 114, 101, 116
        };
        return new String(raw, StandardCharsets.UTF_8);
    }

    public static String viaReflection() throws Exception {
        Method m = String.class.getDeclaredMethod("valueOf", char[].class);
        return (String) m.invoke(null, "reflect-built-secret".toCharArray());
    }

    public static void runAll() {
        try {
            Log.i(TAG, "strings.url=" + decryptUrl());
            Log.i(TAG, "strings.builder=" + viaBuilder("built-", "with-builder"));
            Log.i(TAG, "strings.ctor=" + viaNewString());
            Log.i(TAG, "strings.reflect=" + viaReflection());
            Log.i(TAG, "STRINGS ok");
        } catch (Exception e) {
            Log.e(TAG, "STRINGS failed", e);
        }
    }

    public static long hotLoop(int n) {
        long acc = 0;
        for (int i = 0; i < n; i++) {
            StringBuilder sb = new StringBuilder();
            sb.append("iter-").append(i).append('-').append(i * 7);
            acc += sb.toString().length();
        }
        return acc;
    }
}
