package com.apkdbg.cryptofixture;

import android.app.Activity;
import android.content.ContextWrapper;
import android.content.Intent;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;

/**
 * Launchable fixture activity for apkdbg watch_framework (#27).
 * Trigger deterministically with:
 *
 *   am start -n com.apkdbg.cryptofixture/.FixtureActivity --es op nav
 *   am start -n com.apkdbg.cryptofixture/.FixtureActivity --es op store
 *   am start -n com.apkdbg.cryptofixture/.FixtureActivity --es op svc
 *
 * navPaths() covers, in order:
 *   (a) Activity.startActivity(Intent) — through THIS activity's own
 *       override, which calls super (override + superclass body observed);
 *   (b) Activity.startActivity(Intent, Bundle) — the overloaded call,
 *       NOT overridden here, so the framework body runs directly;
 *   (c) ContextWrapper.startActivity(Intent) — a wrapper around the base
 *       context; traverses ContextWrapper -> ContextImpl, never Activity;
 *   (d) an override that BYPASSES the superclass body: no framework
 *       startActivity method runs, no navigation happens, and a watcher
 *       must record NOTHING for this attempt (the log marker is the
 *       ground truth that it was tried).
 * The activity's own onCreate calls super.onCreate, so launching it is
 * also an observed lifecycle/destination event.
 */
public class FixtureActivity extends Activity {
    private static final String TAG = "CryptoFixture";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        TextView tv = new TextView(this);
        tv.setText("apkdbg framework fixture");
        setContentView(tv);
        String op = getIntent() == null ? null
                : getIntent().getStringExtra("op");
        if ("nav".equals(op)) {
            navPaths();
        } else if ("store".equals(op)) {
            FrameworkWork.storagePaths(this);
            FrameworkWork.customEditorPaths();
        } else if ("svc".equals(op)) {
            FrameworkWork.servicePaths(this);
        }
    }

    void navPaths() {
        // (a) Activity.startActivity(Intent) via the super-calling override
        Intent i1 = new Intent(this, SecondActivity.class);
        i1.putExtra("via", "activity");
        startActivity(i1);

        // (b) the (Intent, Bundle) overload, not overridden here
        Intent i2 = new Intent(this, SecondActivity.class);
        i2.putExtra("via", "activity-opts");
        startActivity(i2, null);

        // (c) ContextWrapper path: wrapper around the base context —
        // traverses ContextWrapper -> ContextImpl, bypasses Activity
        ContextWrapper cw = new ContextWrapper(getBaseContext());
        Intent i3 = new Intent(this, SecondActivity.class);
        i3.putExtra("via", "contextwrapper");
        i3.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        cw.startActivity(i3);

        // (d) bypass override: the superclass body never runs
        Intent i4 = new Intent(this, SecondActivity.class);
        i4.putExtra("bypass", true);
        startActivity(i4);

        Log.i(TAG, "FW NAV ok");
    }

    @Override
    public void startActivity(Intent intent) {
        if (intent != null && intent.getBooleanExtra("bypass", false)) {
            // override that BYPASSES the superclass body: no framework
            // startActivity executes, no navigation is attempted
            Log.i(TAG, "FW NAV bypass superclass-body-skipped");
            return;
        }
        super.startActivity(intent);
    }
}
