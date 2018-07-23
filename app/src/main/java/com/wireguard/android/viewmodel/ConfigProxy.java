package com.wireguard.android.viewmodel;

import android.databinding.ObservableArrayList;
import android.databinding.ObservableList;

import com.wireguard.config.Config;

import java.util.List;

import java9.util.stream.Collectors;
import java9.util.stream.StreamSupport;

public class ConfigProxy {
    private final InterfaceProxy interfaze;
    private final ObservableList<PeerProxy> peers = new ObservableArrayList<>();

    public ConfigProxy(final Config config) {
        interfaze = new InterfaceProxy(config.getInterface());
        final List<PeerProxy> peerProxies = StreamSupport.stream(config.getPeers())
                .map(peer -> new PeerProxy(this, peer))
                .collect(Collectors.toList());
        peers.addAll(peerProxies);
    }

    public ConfigProxy() {
        interfaze = new InterfaceProxy();
    }

    public PeerProxy addPeer() {
        final PeerProxy peer = new PeerProxy(this);
        peers.add(peer);
        return peer;
    }

    public InterfaceProxy getInterface() {
        return interfaze;
    }

    public ObservableList<PeerProxy> getPeers() {
        return peers;
    }

    public Config resolve() {
        return new Config.Builder()
                .setInterface(interfaze.resolve())
                .addPeers(StreamSupport.stream(peers)
                        .map(PeerProxy::resolve)
                        .collect(Collectors.toList()))
                .build();
    }
}
