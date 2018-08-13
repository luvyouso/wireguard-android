/*
 * Copyright © 2018 Harsh Shandilya <msfjarvis@gmail.com>
 * Copyright © 2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.wireguard.android.widget.fab;

import android.content.Context;
import android.support.design.widget.CoordinatorLayout;
import android.support.design.widget.Snackbar;

import android.annotation.NonNull;
import android.util.AttributeSet;
import android.view.View;

public class FloatingActionButtonBehavior extends CoordinatorLayout.Behavior<FloatingActionsMenu> {
    public FloatingActionButtonBehavior(final Context context, final AttributeSet attrs) {
        super(context, attrs);
    }

    @Override
    public boolean layoutDependsOn(@NonNull final CoordinatorLayout parent, @NonNull final FloatingActionsMenu child,
                                   @NonNull final View dependency) {
        return dependency instanceof Snackbar.SnackbarLayout;
    }

    @Override
    public boolean onDependentViewChanged(@NonNull final CoordinatorLayout parent, @NonNull final FloatingActionsMenu child,
                                          @NonNull final View dependency) {
        child.setBehaviorYTranslation(Math.min(0, dependency.getTranslationY() - dependency.getMeasuredHeight()));
        return true;
    }

    @Override
    public void onDependentViewRemoved(@NonNull final CoordinatorLayout parent, @NonNull final FloatingActionsMenu child,
                                       @NonNull final View dependency) {
        // TODO(msf): animate this so it isn't so dramatic when the snackbar is swiped away
        child.setBehaviorYTranslation(0);
    }
}
