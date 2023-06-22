/*
 * Copyright (C) 2023 ArrowOS
 *           (C) 2024 LeafOS Project
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */
package com.android.systemui.biometrics

import android.content.ContentResolver
import android.content.Context
import android.provider.Settings
import javax.inject.Inject

class FingerprintInteractiveToAuthProviderImpl @Inject constructor(
    private val mContext: Context
) : FingerprintInteractiveToAuthProvider {
    private val mDefaultValue: Int

    init {
        mDefaultValue = if (mContext.resources.getBoolean(
                com.android.internal.R.bool.config_performantAuthDefault
            )
        ) 1 else 0
    }

    override val enabledForCurrentUser: Flow<Boolean>
        get() = flow {
            val resolver: ContentResolver = mContext.contentResolver
            var value: Int = Settings.Secure.getIntForUser(
                resolver,
                Settings.Secure.SFPS_PERFORMANT_AUTH_ENABLED,
                -1,
                resolver.getUserId()
            )
            if (value == -1) {
                value = mDefaultValue
                Settings.Secure.putIntForUser(
                    resolver,
                    Settings.Secure.SFPS_PERFORMANT_AUTH_ENABLED,
                    value,
                    resolver.getUserId()
                )
            }
            emit(value == 0)
        }
}
