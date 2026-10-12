package com.apkdbg.cryptofixture;

import android.util.Log;

import java.nio.ByteBuffer;
import java.security.MessageDigest;

/**
 * Deterministic buffer corpus for apkdbg export_buffer validation (#38).
 * Handles com.apkdbg.cryptofixture.BUFFERS: build() fills and RETAINS the
 * corpus in static fields so every object stays reachable for JDWP
 * inspection after the broadcast returns. Ground truth — SHA-256 over
 * each artifact's [position, limit) window (or full array) — is logged to
 * logcat under tag CryptoFixture so the host can compare:
 *
 *   BUFFER <name> kind=<kind> range=[<start>,<end>) sha256=<hex>
 *
 * The 64 KiB corpus is reproducible host-side: LCG x = (x*1103515245 +
 * 12345) & 0x7fffffff starting at SEED, byte i = (x >>> 16) & 0xff.
 */
public class BufferWork {
    private static final String TAG = "CryptoFixture";
    public static final int SEED = 0x5EED;
    public static final int ARRAY_LEN = 64 * 1024;

    public static byte[] corpus;        // 64 KiB deterministic (LCG, SEED)
    public static ByteBuffer heapView;  // position 4096, limit 61440
    public static ByteBuffer slice;     // slice of heapView: pos 16, lim 1000
    public static ByteBuffer nestedSlice; // slice of slice: pos 4, lim 500
    public static byte[] empty;         // zero-length array
    public static ByteBuffer readOnly;  // read-only view of heapView
    public static ByteBuffer direct;    // direct buffer: pos 32, lim 224

    public static void build() {
        corpus = new byte[ARRAY_LEN];
        int x = SEED;
        for (int i = 0; i < corpus.length; i++) {
            x = (x * 1103515245 + 12345) & 0x7fffffff;
            corpus[i] = (byte) (x >>> 16);
        }
        empty = new byte[0];

        heapView = ByteBuffer.wrap(corpus);
        heapView.position(4096);
        heapView.limit(61440);

        slice = heapView.slice();
        slice.position(16);
        slice.limit(1000);

        nestedSlice = slice.slice();
        nestedSlice.position(4);
        nestedSlice.limit(500);

        readOnly = heapView.asReadOnlyBuffer();

        direct = ByteBuffer.allocateDirect(256);
        for (int i = 0; i < 256; i++) {
            direct.put(i, (byte) (i ^ 0xA5));
        }
        direct.position(32);
        direct.limit(224);

        logArray("corpus", corpus);
        logArray("empty", empty);
        logBuffer("heapView", heapView);
        logBuffer("slice", slice);
        logBuffer("nestedSlice", nestedSlice);
        logBuffer("direct", direct);
        Log.i(TAG, "BUFFER readOnly kind=" + readOnly.getClass().getName()
                + " (export_buffer v1: capability error expected)");
        Log.i(TAG, "BUFFERS ok");
    }

    private static void logArray(String name, byte[] a) {
        Log.i(TAG, "BUFFER " + name + " kind=byte[] range=[0," + a.length
                + ") sha256=" + sha256(a));
    }

    private static void logBuffer(String name, ByteBuffer b) {
        ByteBuffer d = b.duplicate();   // read-only cursor: no mutation
        byte[] data = new byte[d.remaining()];
        d.get(data);
        Log.i(TAG, "BUFFER " + name + " kind=" + b.getClass().getName()
                + " range=[" + b.position() + "," + b.limit()
                + ") sha256=" + sha256(data));
    }

    private static String sha256(byte[] data) {
        try {
            return RunReceiver.hex(
                    MessageDigest.getInstance("SHA-256").digest(data));
        } catch (Exception e) {
            return "error:" + e;
        }
    }
}
