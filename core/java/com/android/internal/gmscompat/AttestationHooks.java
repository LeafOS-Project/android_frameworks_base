/*
 * Copyright (C) 2021 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.internal.gmscompat;

import android.app.Application;
import android.os.Build;
import android.os.SystemProperties;
import android.util.Log;

import java.lang.reflect.Field;
import java.util.Arrays;

/** @hide */
public final class AttestationHooks {
    private static final String TAG = "GmsCompat/Attestation";
    private static final String PACKAGE_GMS = "com.google.android.gms";
    private static final String FAKE_FINGERPRINT = "google/barbet/barbet:12/SP1A.210812.015/7679548:user/release-keys";
    private static final String FAKE_SPL = "2021-10-05";

    private static volatile boolean sIsGms = false;

    private AttestationHooks() { }

    private static void setBuildField(String key, Object value) {
        try {
            // Unlock
            Field field = Build.class.getDeclaredField(key);
            field.setAccessible(true);

            // Edit
            field.set(null, value);

            // Lock
            field.setAccessible(false);
        } catch (NoSuchFieldException | IllegalAccessException e) {
            Log.e(TAG, "Failed to spoof Build." + key, e);
        }
    }

    private static void spoofBuildGms() {
        // Alter model name to avoid hardware attestation enforcement
        setBuildField("MODEL", Build.MODEL + " ");
        setBuildField("FINGERPRINT", FAKE_FINGERPRINT);
        setBuildField("SECURITY_PATCH", FAKE_SPL);
        setBuildField("TAGS", "release-keys");
        setBuildField("TYPE", "user");
        setBuildField("IS_DEBUGGABLE", false);
        setBuildField("BRAND", "google");
        setBuildField("MANUFACTURER", "google");
    }

    public static void initApplicationBeforeOnCreate(Application app) {
        if (PACKAGE_GMS.equals(app.getPackageName())) {
            sIsGms = true;
            spoofBuildGms();
        }
    }

    public static String maybeSpoofProperty(String key) {
        if (sIsGms) {
            switch (key) {
                case "ro.vendor.build.fingerprint":
                case "ro.build.fingerprint": return FAKE_FINGERPRINT;
                case "ro.build.tags": return "release-keys";
                case "ro.build.type": return "user";
                case "ro.build.version.security_patch": return FAKE_SPL;
                case "ro.debuggable": return "0";
                case "ro.secure": return "1";
                case "service.adb.root": return "";
                default: return null;
            }
        }
        return null;
    }

    private static boolean isCallerSafetyNet() {
        return Arrays.stream(Thread.currentThread().getStackTrace())
                .anyMatch(elem -> elem.getClassName().contains("DroidGuard"));
    }

    public static void onEngineGetCertificateChain() {
        // Check stack for SafetyNet
        if (sIsGms && isCallerSafetyNet()) {
            throw new UnsupportedOperationException();
        }
    }
}
