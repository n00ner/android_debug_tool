package com.apkdbg.cryptofixture;

import android.app.AlarmManager;
import android.content.Context;
import android.content.SharedPreferences;
import android.util.Log;

/**
 * Framework-watcher fixture paths for apkdbg watch_framework (#27).
 * Every method runs against a real (non-restricted) Context.
 *
 * storagePaths(): SharedPreferences staged edits vs submissions —
 *   apply path, commit path (result logged as ground truth), a DISCARDED
 *   editor (staged, never submitted), two interleaved concurrent editors,
 *   and a clear+apply path.
 * customEditorPaths(): a custom SharedPreferences$Editor implementation
 *   (CustomEditor) — invisible to the AOSP impl alternates; watched only
 *   via an explicit custom profile or defer auto-install.
 * servicePaths(): string-based and class-based getSystemService lookups,
 *   plus repeated hot lookups of the same service.
 * benchLoop(): high-frequency storage+service workload for the #27
 *   benchmark harness (FW_BENCH action).
 */
public class FrameworkWork {
    private static final String TAG = "CryptoFixture";

    public static void storagePaths(Context ctx) {
        SharedPreferences prefs =
                ctx.getSharedPreferences("framework_fixture", 0);

        // apply path: staged edits then asynchronous submission
        SharedPreferences.Editor e1 = prefs.edit();
        e1.putString("greeting", "hello-framework");
        e1.putInt("counter", 7);
        e1.remove("stale-key");
        e1.apply();

        // commit path: synchronous submission with a boolean result
        SharedPreferences.Editor e2 = prefs.edit();
        e2.putLong("timestamp", 123456789L);
        e2.putBoolean("flag", true);
        boolean committed = e2.commit();
        Log.i(TAG, "FW store.commit=" + committed);

        // discarded editor: staged edit, never submitted
        SharedPreferences.Editor e3 = prefs.edit();
        e3.putString("discarded-key", "never-submitted");

        // concurrent editors interleaved: two live editors must not be
        // conflated into one transaction
        SharedPreferences.Editor a = prefs.edit();
        SharedPreferences.Editor b = prefs.edit();
        a.putString("a-key", "A");
        b.putString("b-key", "B");
        a.apply();
        boolean bOk = b.commit();
        Log.i(TAG, "FW store.concurrent.commit=" + bOk);

        // clear path
        SharedPreferences.Editor e4 = prefs.edit();
        e4.clear();
        e4.apply();

        Log.i(TAG, "FW STORE ok");
    }

    public static void customEditorPaths() {
        CustomEditor ed = new CustomEditor();
        ed.putString("custom-key", "custom-value");
        ed.putFloat("custom-float", 1.5f);
        boolean ok = ed.commit();
        // a second, discarded custom editor
        CustomEditor ed2 = new CustomEditor();
        ed2.putBoolean("custom-discarded", true);
        Log.i(TAG, "FW custom.commit=" + ok);
    }

    public static void servicePaths(Context ctx) {
        Object am = ctx.getSystemService(Context.ACTIVITY_SERVICE);
        Object alarm = ctx.getSystemService(AlarmManager.class);
        // repeated/hot lookups of the same capability
        for (int i = 0; i < 5; i++) {
            ctx.getSystemService(Context.ALARM_SERVICE);
        }
        Log.i(TAG, "FW SVC ok am=" + (am != null)
                + " alarm=" + (alarm != null));
    }

    public static long benchLoop(Context ctx, int n) {
        long acc = 0;
        SharedPreferences prefs = ctx.getSharedPreferences("fw_bench", 0);
        for (int i = 0; i < n; i++) {
            prefs.edit().putInt("k" + (i % 16), i).apply();
            Object o = ctx.getSystemService(Context.ALARM_SERVICE);
            if (o != null) {
                acc++;
            }
        }
        return acc;
    }
}
