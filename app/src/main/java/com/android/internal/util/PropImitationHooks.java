/*
 * Copyright (C) 2022-2024 Paranoid Android
 *           (C) 2023 ArrowOS
 *           (C) 2023 The LibreMobileOS Foundation
 *           (C) 2025 Vulcanzier
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.internal.util;

import android.app.ActivityTaskManager;
import android.app.Application;
import android.app.TaskStackListener;
import android.content.ComponentName;
import android.content.Context;
import android.content.res.Resources;
import android.os.Build;
import android.os.Binder;
import android.os.Process;
import android.os.SystemProperties;
import android.text.TextUtils;
import android.util.Log;

import org.lsposed.lsparanoid.Obfuscate;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

/**
 * @hide
 */
@Obfuscate
public class PropImitationHooks {

    private static final String TAG = "Luph-PropImitationHooks";
    private static final boolean DEBUG = true;

    private static final Boolean sDisableGmsProps = SystemProperties.getBoolean("persist.sys.vulcan.disable.gms_props", false);

    private static final String PACKAGE_ARCORE = "com.google.ar.core";
    private static final String PACKAGE_FINSKY = "com.android.vending";
    private static final String PACKAGE_GMS = "com.google.android.gms";
    private static final String PROCESS_GMS_UNSTABLE = PACKAGE_GMS + ".unstable";
    private static final String PACKAGE_NETFLIX = "com.netflix.mediaclient";
    private static final String PACKAGE_GPHOTOS = "com.google.android.apps.photos";


    private static final ComponentName GMS_ADD_ACCOUNT_ACTIVITY = ComponentName.unflattenFromString(
            "com.google.android.gms/.auth.uiflows.minutemaid.MinuteMaidActivity");

    private static final Set<String> sPixelFeatures = Set.of(
            "PIXEL_2017_PRELOAD",
            "PIXEL_2018_PRELOAD",
            "PIXEL_2019_MIDYEAR_PRELOAD",
            "PIXEL_2019_PRELOAD",
            "PIXEL_2020_EXPERIENCE",
            "PIXEL_2020_MIDYEAR_EXPERIENCE",
            "PIXEL_EXPERIENCE"
    );

    private static final String[] packagesToChangeRecentPixel = {
            "com.amazon.avod.thirdpartyclient",
            "com.android.chrome",
            "com.breel.wallpapers20",
            "com.disney.disneyplus",
            "com.disney.disneyplus",
            "com.google.android.aicore",
            "com.google.android.apps.accessibility.magnifier",
            "com.google.android.apps.bard",
            "com.google.android.apps.customization.pixel",
            "com.google.android.apps.emojiwallpaper",
            "com.google.android.apps.nexuslauncher",
            "com.google.android.apps.pixel.agent",
            "com.google.android.apps.pixel.creativeassistant",
            "com.google.android.apps.pixel.support",
            "com.google.android.apps.privacy.wildlife",
            "com.google.android.apps.subscriptions.red",
            "com.google.android.apps.weather",
            "com.google.android.googlequicksearchbox",
            "com.google.android.wallpaper.effects",
            "com.google.pixel.livewallpaper",
            "com.microsoft.android.smsorganizer",
            "com.nhs.online.nhsonline",
            "in.startv.hotstar",
            "jp.id_credit_sp2.android"
    };

    private static final String[] packagesToChangeToPixelXL = {
            "com.snapchat.android",
            "com.google.android.apps.photos"
    };


    private static volatile List<String> sCertifiedProps, recentPixel, pixelXL;
    private static volatile String sNetflixModel;

    private static volatile String sProcessName;
    private static volatile boolean sIsGms, sIsFinsky, sIsPhotos;

    private static List<String> parseFingerprint(String fingerprint) {
        String[] parts = fingerprint.split("/");
        return List.of(
                "FINGERPRINT:" + fingerprint,
                "BRAND:" + parts[0],
                "PRODUCT:" + parts[1],
                "DEVICE:" + parts[2].split(":")[0],
                "VERSION.RELEASE:" + parts[2].split(":")[1],
                "ID:" + parts[3],
                "VERSION.INCREMENTAL:" + parts[4].split(":")[0],
                "TYPE:" + parts[4].split(":")[1],
                "TAGS:" + parts[5]
        );
    }

    public static void setProps(Context context) {
        final String packageName = context.getPackageName();
        final String processName = Application.getProcessName();

        if (TextUtils.isEmpty(packageName) || TextUtils.isEmpty(processName)) {
            Log.e(TAG, "Null package or process name");
            return;
        }

        final Resources res = context.getResources();
        if (res == null) {
            Log.e(TAG, "Null resources");
            return;
        }

        sCertifiedProps = new ArrayList<>(parseFingerprint(SystemProperties.get("persist.sys.vulcan.FINGERPRINT", "google/oriole_beta/oriole:Baklava/BP21.241121.009/12787338:user/release-keys")));
        sCertifiedProps.add("MODEL:" + SystemProperties.get("persist.sys.vulcan.MODEL", "Pixel 6"));
        sCertifiedProps.add("MANUFACTURER:" + SystemProperties.get("persist.sys.vulcan.MANUFACTURER", "Google"));
        sCertifiedProps.add("VERSION.SECURITY_PATCH:" + SystemProperties.get("persist.sys.vulcan.security_patch", "2024-12-05"));
        sCertifiedProps.add("VERSION.DEVICE_INITIAL_SDK_INT:" + SystemProperties.get("persist.sys.vulcan.first_api_level", "21"));

        recentPixel = new ArrayList<>(parseFingerprint("google/komodo/komodo:15/AP4A.241205.013/12621605:user/release-keys"));
        recentPixel.add("MANUFACTURER:Google");
        recentPixel.add("MODEL:Pixel 9 Pro XL");

        pixelXL = new ArrayList<>(parseFingerprint("google/marlin/marlin:10/QP1A.191005.007.A3/5972272:user/release-keys"));
        pixelXL.add("MANUFACTURER:Google");
        pixelXL.add("MODEL:Pixel XL");

        sNetflixModel = SystemProperties.get("persist.sys.vulcan.netflixSpoofModel", null);

        sProcessName = processName;
        sIsGms = packageName.equals(PACKAGE_GMS) && processName.equals(PROCESS_GMS_UNSTABLE);
        sIsFinsky = packageName.equals(PACKAGE_FINSKY);
        sIsPhotos = packageName.equals(PACKAGE_GPHOTOS);

        if (sIsGms) {
            dlog("Setting props for GMS");
            setCertifiedPropsForGms();
        } else if (Arrays.asList(packagesToChangeToPixelXL).contains(packageName)) {
            dlog("Setting model to Pixel XL for " + packageName);
            setProps(pixelXL);
        } else if (Arrays.asList(packagesToChangeRecentPixel).contains(packageName)) {
            dlog("Setting model to Pixel 9 Pro XL for " + packageName);
            setProps(recentPixel);
        } else if (sNetflixModel != null && !sNetflixModel.isEmpty() && packageName.equals(PACKAGE_NETFLIX)) {
            dlog("Setting model to " + sNetflixModel + " for Netflix");
            setPropValue("MODEL", sNetflixModel);
        }
    }



    private static void setPropValue(String key, String value) {
        try {
            dlog("Setting prop " + key + " to " + value);
            Class clazz = Build.class;
            if (key.startsWith("VERSION.")) {
                clazz = Build.VERSION.class;
                key = key.substring(8);
            }
            Field field = clazz.getDeclaredField(key);
            field.setAccessible(true);
            // Cast the value to int if it's an integer field, otherwise string.
            field.set(null, field.getType().equals(Integer.TYPE) ? Integer.parseInt(value) : value);
            field.setAccessible(false);
        } catch (Exception e) {
            Log.e(TAG, "Failed to set prop " + key, e);
        }
    }

    private static void setCertifiedPropsForGms() {

        if (sDisableGmsProps) {
            dlog("GMS prop imitation is disabled by user");
            return;
        }

        if (sCertifiedProps.isEmpty()) {
            dlog("Certified props are not set");
            return;
        }

        final boolean was = isGmsAddAccountActivityOnTop();
        final TaskStackListener taskStackListener = new TaskStackListener() {
            @Override
            public void onTaskStackChanged() {
                final boolean is = isGmsAddAccountActivityOnTop();
                if (is ^ was) {
                    dlog("GmsAddAccountActivityOnTop is:" + is + " was:" + was +
                            ", killing myself!"); // process will restart automatically later
                    Process.killProcess(Process.myPid());
                }
            }
        };
        if (!was) {
            dlog("Spoofing build for GMS");
            setProps(sCertifiedProps);
        } else {
            dlog("Skip spoofing build for GMS, because GmsAddAccountActivityOnTop");
        }
        try {
            ActivityTaskManager.getService().registerTaskStackListener(taskStackListener);
        } catch (Exception e) {
            Log.e(TAG, "Failed to register task stack listener!", e);
        }
    }

    private static void setProps(List<String> props) {
        for (String entry : props) {
            // Each entry must be of the format FIELD:value
            final String[] fieldAndProp = entry.split(":", 2);
            if (fieldAndProp.length != 2) {
                Log.e(TAG, "Invalid entry in certified props: " + entry);
                continue;
            }
            setPropValue(fieldAndProp[0], fieldAndProp[1]);
        }
    }

    private static boolean isGmsAddAccountActivityOnTop() {
        try {
            final ActivityTaskManager.RootTaskInfo focusedTask =
                    ActivityTaskManager.getService().getFocusedRootTaskInfo();
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                return focusedTask != null && focusedTask.topActivity != null
                        && focusedTask.topActivity.equals(GMS_ADD_ACCOUNT_ACTIVITY);
            }
        } catch (Exception e) {
            Log.e(TAG, "Unable to get top activity!", e);
        }
        return false;
    }

    public static boolean shouldBypassTaskPermission(Context context) {
        if (context == null) {
            Log.e(TAG, "shouldBypassTaskPermission: context is null");
            return false;
        }

        if (sDisableGmsProps) {
            dlog("Task permission bypass is disabled");
            return false;
        }

        // GMS doesn't have MANAGE_ACTIVITY_TASKS permission
        final int callingUid = Binder.getCallingUid();
        final int gmsUid;
        try {
            gmsUid = context.getPackageManager().getApplicationInfo(PACKAGE_GMS, 0).uid;
        } catch (Exception e) {
            Log.e(TAG, "shouldBypassTaskPermission: unable to get gms uid", e);
            return false;
        }
        dlog("shouldBypassTaskPermission: gmsUid:" + gmsUid + " callingUid:" + callingUid);
        return gmsUid == callingUid;
    }

    public static void onEngineGetCertificateChain() {
        dlog("onEngineGetCertificateChain");
    }

    public static boolean hasSystemFeature(String name, boolean has) {
        if (sIsPhotos && has
                && sPixelFeatures.stream().anyMatch(name::contains)) {
            dlog("Blocked system feature " + name + " for Google Photos");
            has = false;
        }
        return has;
    }

    public static void dlog(String msg) {
        if (DEBUG) Log.d(TAG, "[" + sProcessName + "] " + msg);
    }
}