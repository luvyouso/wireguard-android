/*
 * Copyright © 2018 Eric Kuck <eric@bluelinelabs.com>.
 * Copyright © 2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.wireguard.android.fragment;

import android.app.Activity;
import android.app.Dialog;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.databinding.ObservableArrayList;
import android.databinding.ObservableList;
import android.os.Bundle;
import android.support.annotation.Nullable;
import android.support.v4.app.DialogFragment;
import android.support.v4.app.Fragment;
import android.support.v7.app.AlertDialog;
import android.widget.Toast;

import com.wireguard.android.Application;
import com.wireguard.android.R;
import com.wireguard.android.databinding.AppListDialogFragmentBinding;
import com.wireguard.android.model.ApplicationData;
import com.wireguard.android.util.ExceptionLoggers;
import com.wireguard.android.util.ObservableKeyedArrayList;
import com.wireguard.android.util.ObservableKeyedList;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import java9.util.Comparators;

public class AppListDialogFragment extends DialogFragment {
    private final ObservableKeyedList<String, ApplicationData> appData =
            new ObservableKeyedArrayList<>();
    @Nullable
    private ObservableList<String> excludedApplications;

    public static <T extends Fragment & AppExclusionListener>
    AppListDialogFragment newInstance(final T target) {
        final AppListDialogFragment fragment = new AppListDialogFragment();
        fragment.setTargetFragment(target, 0);
        return fragment;
    }

    private void loadData() {
        final Activity activity = getActivity();
        if (activity == null) {
            return;
        }

        final PackageManager pm = activity.getPackageManager();
        Application.getAsyncWorker().supplyAsync(() -> {
            final Intent launcherIntent = new Intent(Intent.ACTION_MAIN, null);
            launcherIntent.addCategory(Intent.CATEGORY_LAUNCHER);
            final List<ResolveInfo> resolveInfos = pm.queryIntentActivities(launcherIntent, 0);

            final List<ApplicationData> appData = new ArrayList<>();
            for (ResolveInfo resolveInfo : resolveInfos) {
                String packageName = resolveInfo.activityInfo.packageName;
                appData.add(new ApplicationData(resolveInfo.loadIcon(pm),
                        resolveInfo.loadLabel(pm).toString(), packageName,
                        excludedApplications.contains(packageName)));
            }

            Collections.sort(appData, Comparators.comparing(ApplicationData::getName, String.CASE_INSENSITIVE_ORDER));
            return appData;
        }).whenComplete(((data, throwable) -> {
            if (data != null) {
                appData.clear();
                appData.addAll(data);
            } else {
                final String error = throwable != null ? ExceptionLoggers.unwrapMessage(throwable) : "Unknown";
                final String message = activity.getString(R.string.error_fetching_apps, error);
                Toast.makeText(activity, message, Toast.LENGTH_LONG).show();
                dismissAllowingStateLoss();
            }
        }));
    }

    @Override
    public void onCreate(@Nullable final Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        if (getTargetFragment() instanceof AppExclusionListener)
            excludedApplications = ((AppExclusionListener) getTargetFragment()).onRequestExcludedApplications();
        else
            excludedApplications = new ObservableArrayList<>();
    }

    @Override
    public Dialog onCreateDialog(final Bundle savedInstanceState) {
        final AlertDialog.Builder alertDialogBuilder = new AlertDialog.Builder(getActivity());
        alertDialogBuilder.setTitle(R.string.excluded_applications);

        final AppListDialogFragmentBinding binding =
                AppListDialogFragmentBinding.inflate(getActivity().getLayoutInflater(), null, false);
        binding.executePendingBindings();
        alertDialogBuilder.setView(binding.getRoot());

        alertDialogBuilder.setPositiveButton(R.string.set_exclusions, (dialog, which) -> setExclusionsAndDismiss());
        alertDialogBuilder.setNegativeButton(R.string.cancel, (dialog, which) -> dialog.dismiss());
        alertDialogBuilder.setNeutralButton(R.string.deselect_all, (dialog, which) -> {
            for (final ApplicationData app : appData)
                app.setExcludedFromTunnel(false);
        });

        binding.setFragment(this);
        binding.setAppData(appData);

        loadData();

        return alertDialogBuilder.create();
    }

    void setExclusionsAndDismiss() {
        final List<String> excludedApps = new ArrayList<>();
        for (final ApplicationData data : appData) {
            if (data.isExcludedFromTunnel() && !excludedApps.contains(data.getPackageName())) {
                excludedApps.add(data.getPackageName());
            }
        }
        dismiss();
    }

    public interface AppExclusionListener {
        ObservableList<String> onRequestExcludedApplications();
    }

}
