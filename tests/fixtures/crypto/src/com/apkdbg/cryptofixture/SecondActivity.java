package com.apkdbg.cryptofixture;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;

/**
 * Navigation destination for the #27 fixture: its onCreate calls
 * super.onCreate, so a started SecondActivity is an OBSERVED lifecycle
 * event (nav.lifecycle.oncreate) whose attributed caller is this class.
 */
public class SecondActivity extends Activity {
    private static final String TAG = "CryptoFixture";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        TextView tv = new TextView(this);
        String via = getIntent() == null ? "?"
                : getIntent().getStringExtra("via");
        tv.setText("second: " + via);
        setContentView(tv);
        Log.i(TAG, "FW NAV destination SecondActivity via=" + via);
    }
}
