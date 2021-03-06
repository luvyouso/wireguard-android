/*
 * Copyright © 2018 Samuel Holland <samuel@sholland.org>
 * Copyright © 2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.wireguard.android.util;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.support.design.widget.Snackbar;
import android.view.View;
import android.widget.TextView;

import com.wireguard.android.widget.MonkeyedSnackbar;

/**
 * Standalone utilities for interacting with the system clipboard.
 */

public final class ClipboardUtils {
    private ClipboardUtils() {
        // Prevent instantiation
    }

    public static void copyTextView(final View view) {
        if (!(view instanceof TextView))
            return;
        final CharSequence text = ((TextView) view).getText();
        if (text == null || text.length() == 0)
            return;
        final Object service = view.getContext().getSystemService(Context.CLIPBOARD_SERVICE);
        if (!(service instanceof ClipboardManager))
            return;
        final CharSequence description = view.getContentDescription();
        ((ClipboardManager) service).setPrimaryClip(ClipData.newPlainText(description, text));
        MonkeyedSnackbar.make(view, description + " copied to clipboard", Snackbar.LENGTH_LONG).show();
    }
}
