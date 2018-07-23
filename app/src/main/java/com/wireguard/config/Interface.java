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
import com.wireguard.crypto.KeyPair;

import java.net.InetAddress;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Matcher;

import java9.util.Lists;
import java9.util.Optional;
import java9.util.stream.Collectors;
import java9.util.stream.Stream;

/**
 * Represents the configuration for a WireGuard interface (an [Interface] block). Interfaces must
 * have a private key (used to initialize a {@code KeyPair}), and may optionally have several other
 * attributes.
 * <p>
 * Instances of this class are immutable.
 */

public final class Interface {
    private static final int MAX_UDP_PORT = 65535;
    private static final int MIN_IPV6_MTU = 1280;
    private static final int MIN_UDP_PORT = 1;

    private final Set<InetNetwork> addresses;
    private final Set<InetAddress> dnsServers;
    private final Set<String> excludedApplications;
    private final KeyPair keyPair;
    private final Optional<Integer> listenPort;
    private final Optional<Integer> mtu;

    private Interface(final Builder builder) {
        // Defensively copy to ensure immutability even if the Builder is reused.
        addresses = Collections.unmodifiableSet(new ArraySet<>(builder.addresses));
        dnsServers = Collections.unmodifiableSet(new ArraySet<>(builder.dnsServers));
        excludedApplications =
                Collections.unmodifiableSet(new ArraySet<>(builder.excludedApplications));
        keyPair = Objects.requireNonNull(builder.keyPair, "Interfaces must have a private key");
        listenPort = builder.listenPort;
        mtu = builder.mtu;
    }

    /**
     * Parses an series of "KEY = VALUE" lines into an {@code Interface}.
     *
     * @param lines An iterable sequence of lines, containing at least a private key attribute
     * @return An {@code Interface} with all of the attributes from {@code lines} set
     */
    public static Interface parse(final Iterable<? extends CharSequence> lines) {
        final Builder builder = new Builder();
        for (final CharSequence line : lines) {
            final Matcher matcher = Config.LINE_PARSER.matcher(line);
            if (!matcher.matches())
                throw new IllegalArgumentException("Bad configuration format in [Interface]");
            final String key = matcher.group(1);
            final String value = matcher.group(2);
            switch (key.toLowerCase()) {
                case "address":
                    builder.parseAddresses(value);
                    break;
                case "dns":
                    builder.parseDnsServers(value);
                    break;
                case "excludedapplications":
                    builder.parseExcludedApplications(value);
                    break;
                case "listenport":
                    builder.parseListenPort(value);
                    break;
                case "mtu":
                    builder.parseMtu(value);
                    break;
                case "privatekey":
                    builder.parsePrivateKey(value);
                    break;
                default:
                    throw new IllegalArgumentException("Unknown [Interface] attribute: " + key);
            }
        }
        return builder.build();
    }

    public Set<InetNetwork> getAddresses() {
        // The collection is already immutable.
        return addresses;
    }

    public Set<InetAddress> getDnsServers() {
        // The collection is already immutable.
        return dnsServers;
    }

    public Set<String> getExcludedApplications() {
        // The collection is already immutable.
        return excludedApplications;
    }

    public KeyPair getKeyPair() {
        return keyPair;
    }

    public Optional<Integer> getListenPort() {
        return listenPort;
    }

    public Optional<Integer> getMtu() {
        return mtu;
    }

    /**
     * Converts the {@code Interface} into a string suitable for debugging purposes. The {@code
     * Interface} is identified by its public key and (if known) the port used for its UDP socket.
     *
     * @return A concise single-line identifier for the {@code Interface}
     */
    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder("(Interface ");
        sb.append(keyPair.getPublicKey().toBase64());
        if (listenPort.isPresent())
            sb.append(" @").append(listenPort.get());
        sb.append(')');
        return sb.toString();
    }

    /**
     * Converts the {@code Interface} into a string suitable for inclusion in a {@code wg-quick}
     * configuration file.
     *
     * @return The {@code Interface} represented as a series of "KEY = VALUE" lines
     */
    public String toWgQuickString() {
        final StringBuilder sb = new StringBuilder();
        if (!addresses.isEmpty())
            sb.append("Address = ").append(TextUtils.join(", ", addresses)).append('\n');
        if (!dnsServers.isEmpty())
            sb.append("DNS = ").append(TextUtils.join(", ", dnsServers)).append('\n');
        if (!excludedApplications.isEmpty()) {
            sb.append("ExcludedApplications = ");
            sb.append(TextUtils.join(", ", excludedApplications)).append('\n');
        }
        if (listenPort.isPresent())
            sb.append("ListenPort = ").append(listenPort.get()).append('\n');
        if (mtu.isPresent())
            sb.append("MTU = ").append(mtu.get()).append('\n');
        sb.append("PrivateKey = ").append(keyPair.getPrivateKey().toBase64()).append('\n');
        return sb.toString();
    }

    @SuppressWarnings("UnusedReturnValue")
    public static final class Builder {
        // Defaults to an empty set.
        private final Set<InetNetwork> addresses = new ArraySet<>();
        // Defaults to an empty set.
        private final Set<InetAddress> dnsServers = new ArraySet<>();
        // Defaults to an empty set.
        private final Set<String> excludedApplications = new ArraySet<>();
        // No default; must be provided before building.
        @Nullable
        private KeyPair keyPair;
        // Defaults to not present.
        private Optional<Integer> listenPort = Optional.empty();
        // Defaults to not present.
        private Optional<Integer> mtu = Optional.empty();

        public Builder addAddress(final InetNetwork address) {
            // TODO(smaeul): Check for overlap (same address, different mask).
            addresses.add(address);
            return this;
        }

        public Builder addAddresses(final Collection<? extends InetNetwork> addresses) {
            // TODO(smaeul): Check for overlap (same address, different mask).
            this.addresses.addAll(addresses);
            return this;
        }

        public Builder addDnsServer(final InetAddress dnsServer) {
            dnsServers.add(dnsServer);
            return this;
        }

        public Builder addDnsServers(final Collection<? extends InetAddress> dnsServers) {
            this.dnsServers.addAll(dnsServers);
            return this;
        }

        public Builder addExcludedApplication(final String app) {
            excludedApplications.add(app);
            return this;
        }

        public Builder addExcludedApplications(final Collection<String> apps) {
            excludedApplications.addAll(apps);
            return this;
        }

        public Interface build() {
            return new Interface(this);
        }

        public Builder parseAddresses(final CharSequence addresses) {
            final List<InetNetwork> newAddresses = Stream.of(Config.LIST_SEPARATOR.split(addresses))
                    .map(InetNetwork::new)
                    .collect(Collectors.toUnmodifiableList());
            return addAddresses(newAddresses);
        }

        public Builder parseDnsServers(final CharSequence dnsServers) {
            final List<InetAddress> newDnsServers = Stream.of(Config.LIST_SEPARATOR.split(dnsServers))
                    .map(InetAddresses::parse)
                    .collect(Collectors.toUnmodifiableList());
            return addDnsServers(newDnsServers);
        }

        public Builder parseExcludedApplications(final CharSequence apps) {
            return addExcludedApplications(Lists.of(Config.LIST_SEPARATOR.split(apps)));
        }

        public Builder parseListenPort(final String listenPort) {
            return setListenPort(Integer.parseInt(listenPort));
        }

        public Builder parseMtu(final String mtu) {
            return setMtu(Integer.parseInt(mtu));
        }

        public Builder parsePrivateKey(final String privateKey) {
            return setKeyPair(new KeyPair(Key.fromBase64(privateKey)));
        }

        public Builder setKeyPair(final KeyPair keyPair) {
            this.keyPair = keyPair;
            return this;
        }

        public Builder setListenPort(final int listenPort) {
            if (listenPort < MIN_UDP_PORT || listenPort > MAX_UDP_PORT)
                throw new IllegalArgumentException("ListenPort must be a valid UDP port number");
            this.listenPort = Optional.of(listenPort);
            return this;
        }

        public Builder setMtu(final int mtu) {
            if (mtu < MIN_IPV6_MTU)
                throw new IllegalArgumentException("MTU must be at least " + MIN_IPV6_MTU);
            this.mtu = Optional.of(mtu);
            return this;
        }
    }
}
