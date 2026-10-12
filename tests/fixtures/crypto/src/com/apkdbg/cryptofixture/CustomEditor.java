package com.apkdbg.cryptofixture;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import android.content.SharedPreferences;

/**
 * Custom SharedPreferences.Editor implementation for apkdbg
 * watch_framework validation (#27): SharedPreferences$Editor is an
 * interface, so the AOSP impl alternates never observe THIS class — it
 * stands in for custom/late-loaded implementations that only an explicit
 * custom profile (or defer auto-install) can watch. Staged edits live in
 * a plain Map; commit() reports a deterministic boolean result.
 *
 * Methods return the interface type (not CustomEditor): covariant return
 * overrides make javac emit bridge methods that crash d8 30.0.3.
 */
public class CustomEditor implements SharedPreferences.Editor {
    private final Map<String, Object> staged = new HashMap<>();
    private boolean clearFlag = false;
    boolean submitted = false;

    @Override
    public SharedPreferences.Editor putString(String key, String value) {
        staged.put(key, value);
        return this;
    }

    @Override
    public SharedPreferences.Editor putStringSet(String key,
                                                 Set<String> values) {
        staged.put(key, values);
        return this;
    }

    @Override
    public SharedPreferences.Editor putInt(String key, int value) {
        staged.put(key, value);
        return this;
    }

    @Override
    public SharedPreferences.Editor putLong(String key, long value) {
        staged.put(key, value);
        return this;
    }

    @Override
    public SharedPreferences.Editor putFloat(String key, float value) {
        staged.put(key, value);
        return this;
    }

    @Override
    public SharedPreferences.Editor putBoolean(String key, boolean value) {
        staged.put(key, value);
        return this;
    }

    @Override
    public SharedPreferences.Editor remove(String key) {
        staged.remove(key);
        return this;
    }

    @Override
    public SharedPreferences.Editor clear() {
        clearFlag = true;
        staged.clear();
        return this;
    }

    @Override
    public boolean commit() {
        submitted = true;
        return !staged.isEmpty() || clearFlag;
    }

    @Override
    public void apply() {
        submitted = true;
    }

    public int stagedCount() {
        return staged.size();
    }
}
