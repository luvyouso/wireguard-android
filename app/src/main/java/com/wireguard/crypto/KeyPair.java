/*
 * Copyright © 2018 Samuel Holland <samuel@sholland.org>
 * Copyright © 2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.wireguard.crypto;

import java.security.SecureRandom;

/**
 * Represents a Curve25519 keypair as used by WireGuard.
 * <p>
 * Instances of this class are immutable.
 */

public class KeyPair {
    private final Key privateKey;
    private final Key publicKey;

    public KeyPair() {
        this(generatePrivateKey());
    }

    public KeyPair(final Key privateKey) {
        this.privateKey = privateKey;
        publicKey = generatePublicKey(privateKey);
    }

    @SuppressWarnings("MagicNumber")
    private static Key generatePrivateKey() {
        final SecureRandom secureRandom = new SecureRandom();
        final byte[] privateKey = new byte[Key.KEY_LENGTH_BYTES];
        secureRandom.nextBytes(privateKey);
        privateKey[0] &= 248;
        privateKey[31] &= 127;
        privateKey[31] |= 64;
        return Key.fromBytes(privateKey);
    }

    private static Key generatePublicKey(final Key privateKey) {
        final byte[] publicKey = new byte[Key.KEY_LENGTH_BYTES];
        Curve25519.eval(publicKey, 0, privateKey.getBytes(), null);
        return Key.fromBytes(publicKey);
    }

    public Key getPrivateKey() {
        return privateKey;
    }

    public Key getPublicKey() {
        return publicKey;
    }
}
