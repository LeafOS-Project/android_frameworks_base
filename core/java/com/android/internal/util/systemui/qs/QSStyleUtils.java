/*
 * Copyright (C) 2023 The LeafOS Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the
 * License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package com.android.internal.util.systemui.qs;

import android.content.Context;
import com.android.systemui.R;

public class QSStyleUtils {
    public static final String QS_STYLE_ROUND = Settings.Secure.QS_STYLE_ROUND;

    public static boolean isRoundQS(Context context) {
        return context.getResources().getInteger(R.bool.qs_style_round);
    }
}
