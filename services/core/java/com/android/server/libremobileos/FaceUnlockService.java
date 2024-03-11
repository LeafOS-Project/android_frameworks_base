/*
 * Copyright (C) 2023-2024 LibreMobileOS Foundation
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

package com.android.server.libremobileos;

import static android.os.Process.THREAD_PRIORITY_DEFAULT;

import android.content.Context;
import android.content.pm.PackageManager;
import android.util.Slog;

import com.android.server.ServiceThread;
import com.android.server.SystemService;

import com.libremobileos.faceunlock.server.FaceUnlockServer;

public class FaceUnlockService extends SystemService {
    private static final String TAG = "FaceUnlockService";

    private ServiceThread mServiceThread = null;
    private FaceUnlockServer mServer = null;

    public FaceUnlockService(Context context) {
        super(context);
    }

    @Override
    public void onStart() {
        final PackageManager pm = getContext().getPackageManager();
        final boolean supportsFace = pm.hasSystemFeature(PackageManager.FEATURE_FACE);
        if (supportsFace) {
            mServiceThread = new ServiceThread(TAG, THREAD_PRIORITY_DEFAULT, false);
            mServiceThread.start();
            mServer = new FaceUnlockServer(getContext(), mServiceThread.getLooper(),
                    this::publishBinderService);
        } else {
            Slog.i(TAG, "Not using any face sensor.");
        }
    }
}
