/*
 * Copyright © 2018 Samuel Holland <samuel@sholland.org>
 * Copyright © 2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.wireguard.config;

import android.support.annotation.Nullable;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Represents the contents of a wg-quick configuration file, made up of one or more "Interface"
 * sections (combined together), and zero or more "Peer" sections (treated individually).
 * <p>
 * Instances of this class are immutable.
 */

public final class Config {
    static final Pattern LINE_PARSER = Pattern.compile("(\\w+)\\s*=\\s*([^\\s#][^#]*)");
    static final Pattern LIST_SEPARATOR = Pattern.compile("\\s*,\\s*");

    private final Interface interfaze;
    private final List<Peer> peers;

    private Config(final Builder builder) {
        interfaze = Objects.requireNonNull(builder.interfaze, "An [Interface] section is required");
        // Defensively copy to ensure immutability even if the Builder is reused.
        peers = Collections.unmodifiableList(new ArrayList<>(builder.peers));
    }

    public static Config parse(final InputStream stream) throws IOException {
        final Builder builder = new Builder();
        try (final BufferedReader reader = new BufferedReader(new InputStreamReader(stream))) {
            final Collection<String> interfaceLines = new ArrayList<>();
            final Collection<String> peerLines = new ArrayList<>();
            boolean inInterfaceSection = false;
            boolean inPeerSection = false;
            String line;
            while ((line = reader.readLine()) != null) {
                final int commentIndex = line.indexOf('#');
                if (commentIndex != -1)
                    line = line.substring(0, commentIndex);
                line = line.trim();
                if (line.isEmpty())
                    continue;
                if ("[Interface]".equalsIgnoreCase(line)) {
                    // Consume all [Peer] lines read so far.
                    if (inPeerSection) {
                        builder.parsePeer(peerLines);
                        peerLines.clear();
                    }
                    inInterfaceSection = true;
                    inPeerSection = false;
                } else if ("[Peer]".equalsIgnoreCase(line)) {
                    // Consume all [Peer] lines read so far.
                    if (inPeerSection) {
                        builder.parsePeer(peerLines);
                        peerLines.clear();
                    }
                    inInterfaceSection = false;
                    inPeerSection = true;
                } else if (inInterfaceSection) {
                    interfaceLines.add(line);
                } else if (inPeerSection) {
                    peerLines.add(line);
                } else {
                    throw new IllegalArgumentException("Unexpected configuration line: " + line);
                }
            }
            if (!inInterfaceSection && !inPeerSection)
                throw new IllegalArgumentException("Empty configuration");
            // Combine all [Interface] sections in the file.
            builder.parseInterface(interfaceLines);
        }
        return builder.build();
    }

    public Interface getInterface() {
        return interfaze;
    }

    public List<Peer> getPeers() {
        return peers;
    }

    /**
     * Converts the {@code Config} into a string suitable for debugging purposes. The {@code Config}
     * is identified by its interface's public key and the number of peers it has.
     *
     * @return A concise single-line identifier for the {@code Config}
     */
    @Override
    public String toString() {
        return "(Config " + interfaze + " (" + peers.size() + " peers))";
    }

    /**
     * Converts the {@code Config} into a string suitable for use as a {@code wg-quick}
     * configuration file.
     *
     * @return The {@code Config} represented as one [Interface] and zero or more [Peer] sections
     */
    public String toWgQuickString() {
        final StringBuilder sb = new StringBuilder();
        sb.append("[Interface]\n").append(interfaze);
        for (final Peer peer : peers)
            sb.append("\n[Peer]\n").append(peer);
        return sb.toString();
    }

    @SuppressWarnings("UnusedReturnValue")
    public static final class Builder {
        // Defaults to an empty list.
        private final List<Peer> peers = new ArrayList<>();
        // No default; must be provided before building.
        @Nullable
        private Interface interfaze;

        public Builder addPeer(final Peer peer) {
            // TODO(smaeul): Should this be a Set to prevent duplicates? */
            peers.add(peer);
            return this;
        }

        public Builder addPeers(final Collection<Peer> peers) {
            // TODO(smaeul): Should this be a Set to prevent duplicates? */
            this.peers.addAll(peers);
            return this;
        }

        public Config build() {
            return new Config(this);
        }

        public Builder parseInterface(final Iterable<? extends CharSequence> lines) {
            return setInterface(Interface.parse(lines));
        }

        public Builder parsePeer(final Iterable<? extends CharSequence> lines) {
            return addPeer(Peer.parse(lines));
        }

        public Builder setInterface(final Interface interfaze) {
            this.interfaze = interfaze;
            return this;
        }
    }
}
