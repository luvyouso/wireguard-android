package com.wireguard.android.viewmodel;

import android.databinding.BaseObservable;
import android.databinding.Bindable;
import android.databinding.ObservableList;
import android.text.TextUtils;

import com.wireguard.android.BR;
import com.wireguard.config.Peer;
import com.wireguard.crypto.Key;

import java.net.InetSocketAddress;

import java9.util.Lists;

public class PeerProxy extends BaseObservable {
    private static final String IPV4_DEFAULT_ROUTE = "0.0.0.0/0";
    private static final String IPV4_DEFAULT_ROUTE_MOD_RFC1918 = TextUtils.join(", ", Lists.of(
            "0.0.0.0/5", "8.0.0.0/7", "11.0.0.0/8", "12.0.0.0/6", "16.0.0.0/4", "32.0.0.0/3",
            "64.0.0.0/2", "128.0.0.0/3", "160.0.0.0/5", "168.0.0.0/6", "172.0.0.0/12",
            "172.32.0.0/11", "172.64.0.0/10", "172.128.0.0/9", "173.0.0.0/8", "174.0.0.0/7",
            "176.0.0.0/4", "192.0.0.0/9", "192.128.0.0/11", "192.160.0.0/13", "192.169.0.0/16",
            "192.170.0.0/15", "192.172.0.0/14", "192.176.0.0/12", "192.192.0.0/10",
            "193.0.0.0/8", "194.0.0.0/7", "196.0.0.0/6", "200.0.0.0/5", "208.0.0.0/4"
    ));

    private final ConfigProxy parent;
    private String allowedIps;
    private String endpoint;
    private String persistentKeepalive;
    private String preSharedKey;
    private String publicKey;
    private boolean shouldExcludePrivateIps;

    public PeerProxy(final ConfigProxy parent) {
        this.parent = parent;
        allowedIps = "";
        endpoint = "";
        persistentKeepalive = "";
        preSharedKey = "";
        publicKey = "";
    }

    public PeerProxy(final ConfigProxy parent, final Peer peer) {
        this.parent = parent;
        allowedIps = TextUtils.join(", ", peer.getAllowedIps());
        endpoint = peer.getEndpoint().map(InetSocketAddress::toString).orElse("");
        persistentKeepalive = peer.getPersistentKeepalive().map(String::valueOf).orElse("");
        preSharedKey = peer.getPreSharedKey().map(Key::toBase64).orElse("");
        publicKey = peer.getPublicKey().toBase64();
    }

    @Bindable
    public String getAllowedIps() {
        return allowedIps;
    }

    @Bindable
    public boolean getCanExcludePrivateIps() {
        return parent.getPeers().size() == 1 && allowedIps.contains(IPV4_DEFAULT_ROUTE);
    }

    @Bindable
    public String getEndpoint() {
        return endpoint;
    }

    @Bindable
    public String getPersistentKeepalive() {
        return persistentKeepalive;
    }

    @Bindable
    public String getPreSharedKey() {
        return preSharedKey;
    }

    @Bindable
    public String getPublicKey() {
        return publicKey;
    }

    @Bindable
    public boolean getShouldExcludePrivateIps() {
        return shouldExcludePrivateIps;
    }

    public Peer resolve() {
        return new Peer.Builder()
                .parseAllowedIPs(allowedIps)
                .parseEndpoint(endpoint)
                .parsePersistentKeepalive(persistentKeepalive)
                .parsePreSharedKey(preSharedKey)
                .parsePublicKey(publicKey)
                .build();
    }

    public void setAllowedIps(final String allowedIps) {
        this.allowedIps = allowedIps;
        notifyPropertyChanged(BR.allowedIps);
        notifyPropertyChanged(BR.canExcludePrivateIps);
    }

    public void setEndpoint(final String endpoint) {
        this.endpoint = endpoint;
        notifyPropertyChanged(BR.endpoint);
    }

    public void setPersistentKeepalive(final String persistentKeepalive) {
        this.persistentKeepalive = persistentKeepalive;
        notifyPropertyChanged(BR.persistentKeepalive);
    }

    public void setPreSharedKey(final String preSharedKey) {
        this.preSharedKey = preSharedKey;
        notifyPropertyChanged(BR.preSharedKey);
    }

    public void setPublicKey(final String publicKey) {
        this.publicKey = publicKey;
        notifyPropertyChanged(BR.publicKey);
    }

    public void setShouldExcludePrivateIps(final boolean shouldExcludePrivateIps) {
        this.shouldExcludePrivateIps = shouldExcludePrivateIps;
        notifyPropertyChanged(BR.shouldExcludePrivateIps);
    }

    private class Listener extends ObservableList.OnListChangedCallback<ObservableList<PeerProxy>> {
        @Override public void onChanged(final ObservableList<PeerProxy> sender) {
            notifyPropertyChanged(BR.canExcludePrivateIps);
        }

        @Override public void onItemRangeChanged(final ObservableList<PeerProxy> sender,
                                                 final int positionStart, final int itemCount) {
            // Do nothing.
        }

        @Override public void onItemRangeInserted(final ObservableList<PeerProxy> sender,
                                                  final int positionStart, final int itemCount) {
            notifyPropertyChanged(BR.canExcludePrivateIps);
        }

        @Override public void onItemRangeMoved(final ObservableList<PeerProxy> sender,
                                               final int fromPosition, final int toPosition,
                                               final int itemCount) {
            // Do nothing.
        }

        @Override public void onItemRangeRemoved(final ObservableList<PeerProxy> sender,
                                                 final int positionStart, final int itemCount) {
            notifyPropertyChanged(BR.canExcludePrivateIps);
        }
    }
}
