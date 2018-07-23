/*
 * Copyright © 2018 Samuel Holland <samuel@sholland.org>
 * Copyright © 2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.wireguard.config;

import android.support.annotation.Nullable;
import android.support.v4.util.ArraySet;
import android.text.TextUtils;

import com.wireguard.crypto.Key;

import java.net.Inet6Address;
import java.net.InetSocketAddress;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Matcher;

import java9.util.Optional;
import java9.util.stream.Collectors;
import java9.util.stream.Stream;

/**
 * Represents the configuration for a WireGuard peer (a [Peer] block). Peers must have a public key,
 * and may optionally have several other attributes.
 * <p>
 * Instances of this class are immutable.
 */

public final class Peer {
    private final Set<InetNetwork> allowedIps;
    private final Optional<InetSocketAddress> endpoint;
    private final Optional<Integer> persistentKeepalive;
    private final Optional<Key> preSharedKey;
    private final Key publicKey;

    private Peer(final Builder builder) {
        // Defensively copy to ensure immutability even if the Builder is reused.
        allowedIps = Collections.unmodifiableSet(new ArraySet<>(builder.allowedIps));
        endpoint = builder.endpoint;
        persistentKeepalive = builder.persistentKeepalive;
        preSharedKey = builder.preSharedKey;
        publicKey = Objects.requireNonNull(builder.publicKey, "Peers must have a public key");
    }

    /**
     * Parses an series of "KEY = VALUE" lines into a {@code Peer}.
     *
     * @param lines An iterable sequence of lines, containing at least a public key attribute
     * @return A {@code Peer} with all of the attributes from {@code lines} set
     */
    public static Peer parse(final Iterable<? extends CharSequence> lines) {
        final Builder builder = new Builder();
        for (final CharSequence line : lines) {
            final Matcher matcher = Config.LINE_PARSER.matcher(line);
            if (!matcher.matches())
                throw new IllegalArgumentException("Bad configuration format in [Peer]");
            final String key = matcher.group(1);
            final String value = matcher.group(2);
            switch (key.toLowerCase()) {
                case "allowedips":
                    builder.parseAllowedIPs(value);
                    break;
                case "endpoint":
                    builder.parseEndpoint(value);
                    break;
                case "persistentkeepalive":
                    builder.parsePersistentKeepalive(value);
                    break;
                case "presharedkey":
                    builder.parsePreSharedKey(value);
                    break;
                case "publickey":
                    builder.parsePublicKey(value);
                    break;
                default:
                    throw new IllegalArgumentException("Unknown [Peer] attribute: " + key);
            }
        }
        return builder.build();
    }

    public Set<InetNetwork> getAllowedIps() {
        // The collection is already immutable.
        return allowedIps;
    }

    public Optional<InetSocketAddress> getEndpoint() {
        return endpoint;
    }

    public Optional<Integer> getPersistentKeepalive() {
        return persistentKeepalive;
    }

    public Optional<Key> getPreSharedKey() {
        return preSharedKey;
    }

    public Key getPublicKey() {
        return publicKey;
    }

    public Optional<String> getResolvedEndpointString() {
        if (!endpoint.isPresent())
            return Optional.empty();
        InetSocketAddress ep = endpoint.get();
        if (ep.isUnresolved())
            ep = new InetSocketAddress(ep.getHostString(), ep.getPort());
        if (ep.isUnresolved())
            return Optional.empty();
        final String fmt = ep.getAddress() instanceof Inet6Address ? "[%s]:%d" : "%s:%d";
        return Optional.of(String.format(fmt, ep.getAddress().getHostAddress(), ep.getPort()));
    }

    /**
     * Converts the {@code Peer} into a string suitable for debugging purposes. The {@code Peer} is
     * identified by its public key and (if known) its endpoint.
     *
     * @return A concise single-line identifier for the {@code Peer}
     */
    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder("(Peer ");
        sb.append(publicKey.toBase64());
        if (endpoint.isPresent())
            sb.append(" @").append(endpoint.get());
        sb.append(')');
        return sb.toString();
    }

    /**
     * Converts the {@code Peer} into a string suitable for inclusion in a {@code wg-quick}
     * configuration file.
     *
     * @return The {@code Peer} represented as a series of "KEY = VALUE" lines
     */
    public String toWgQuickString() {
        final StringBuilder sb = new StringBuilder();
        if (!allowedIps.isEmpty())
            sb.append("AllowedIPs = ").append(TextUtils.join(", ", allowedIps)).append('\n');
        if (endpoint.isPresent())
            sb.append("Endpoint = ").append(endpoint.get()).append('\n');
        if (persistentKeepalive.isPresent())
            sb.append("PersistentKeepalive = ").append(persistentKeepalive.get()).append('\n');
        if (preSharedKey.isPresent())
            sb.append("PreSharedKey = ").append(preSharedKey.get().toBase64()).append('\n');
        sb.append("PublicKey = ").append(publicKey.toBase64()).append('\n');
        return sb.toString();
    }

    @SuppressWarnings("UnusedReturnValue")
    public static final class Builder {
        // Defaults to an empty set.
        private final Set<InetNetwork> allowedIps = new ArraySet<>();
        // Defaults to not present.
        private Optional<InetSocketAddress> endpoint = Optional.empty();
        // Defaults to not present.
        private Optional<Integer> persistentKeepalive = Optional.empty();
        // Defaults to not present.
        private Optional<Key> preSharedKey = Optional.empty();
        // No default; must be provided before building.
        @Nullable
        private Key publicKey;

        public Builder addAllowedIp(final InetNetwork allowedIp) {
            // TODO(smaeul): Check for overlap (same address, different mask).
            allowedIps.add(allowedIp);
            return this;
        }

        public Builder addAllowedIps(final Collection<? extends InetNetwork> allowedIps) {
            // TODO(smaeul): Check for overlap (same address, different mask).
            this.allowedIps.addAll(allowedIps);
            return this;
        }

        public Peer build() {
            return new Peer(this);
        }

        public Builder parseAllowedIPs(final CharSequence allowedIps) {
            final List<InetNetwork> newAllowedIps = Stream.of(Config.LIST_SEPARATOR.split(allowedIps))
                    .map(InetNetwork::new)
                    .collect(Collectors.toUnmodifiableList());
            return addAllowedIps(newAllowedIps);
        }

        public Builder parseEndpoint(final String endpoint) {
            final int colon = endpoint.lastIndexOf(':');
            final String address = endpoint.substring(0, colon);
            final String port = endpoint.substring(colon + 1);
            final InetSocketAddress newEndpoint =
                    new InetSocketAddress(InetAddresses.parse(address), Integer.parseInt(port));
            return setEndpoint(newEndpoint);
        }

        public Builder parsePersistentKeepalive(final String persistentKeepalive) {
            return setPersistentKeepalive(Integer.parseInt(persistentKeepalive));
        }

        public Builder parsePreSharedKey(final String preSharedKey) {
            return setPreSharedKey(Key.fromBase64(preSharedKey));
        }

        public Builder parsePublicKey(final String publicKey) {
            return setPublicKey(Key.fromBase64(publicKey));
        }

        public Builder setEndpoint(final InetSocketAddress endpoint) {
            this.endpoint = Optional.of(endpoint);
            return this;
        }

        public Builder setPersistentKeepalive(final int persistentKeepalive) {
            if (persistentKeepalive < 1)
                throw new IllegalArgumentException("PersistentKeepalive must be positive");
            this.persistentKeepalive = Optional.of(persistentKeepalive);
            return this;
        }

        public Builder setPreSharedKey(final Key preSharedKey) {
            this.preSharedKey = Optional.of(preSharedKey);
            return this;
        }

        public Builder setPublicKey(final Key publicKey) {
            this.publicKey = publicKey;
            return this;
        }
    }
}
