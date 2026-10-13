package com.apkdbg.cryptofixture.payload;

/**
 * Tiny payload class compiled to DEX at build time (see build.sh),
 * AES-encrypted into assets/encrypted_dex.bin, and decrypted + loaded
 * in-memory by UnpackWork at runtime (issue #28 fixture).
 */
public class Payload {
    public static String hello() {
        return "apkdbg-payload-28";
    }
}
