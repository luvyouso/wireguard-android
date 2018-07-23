package com.wireguard.android.viewmodel;

import android.databinding.BaseObservable;
import android.databinding.Bindable;
import android.databinding.ObservableArrayList;
import android.databinding.ObservableList;
import android.text.TextUtils;

import com.wireguard.android.BR;
import com.wireguard.config.Interface;
import com.wireguard.crypto.Key;
import com.wireguard.crypto.KeyPair;

public class InterfaceProxy extends BaseObservable {
    private final ObservableList<String> excludedApplications = new ObservableArrayList<>();
    private String addresses;
    private String dnsServers;
    private String listenPort;
    private String mtu;
    private String privateKey;
    private String publicKey;

    public InterfaceProxy() {
        addresses = "";
        dnsServers = "";
        listenPort = "";
        mtu = "";
        privateKey = "";
        publicKey = "";
    }

    public InterfaceProxy(final Interface interfaze) {
        addresses = TextUtils.join(", ", interfaze.getAddresses());
        dnsServers = TextUtils.join(", ", interfaze.getDnsServers());
        listenPort = interfaze.getListenPort().map(String::valueOf).orElse("");
        mtu = interfaze.getMtu().map(String::valueOf).orElse("");
        privateKey = interfaze.getKeyPair().getPrivateKey().toBase64();
        publicKey = interfaze.getKeyPair().getPublicKey().toBase64();
    }

    public void generateKeyPair() {
        final KeyPair keyPair = new KeyPair();
        privateKey = keyPair.getPrivateKey().toBase64();
        publicKey = keyPair.getPublicKey().toBase64();
        notifyPropertyChanged(BR.privateKey);
        notifyPropertyChanged(BR.publicKey);
    }

    @Bindable
    public String getAddresses() {
        return addresses;
    }

    @Bindable
    public String getDnsServers() {
        return dnsServers;
    }

    public ObservableList<String> getExcludedApplications() {
        return excludedApplications;
    }

    @Bindable
    public String getListenPort() {
        return listenPort;
    }

    @Bindable
    public String getMtu() {
        return mtu;
    }

    @Bindable
    public String getPrivateKey() {
        return privateKey;
    }

    @Bindable
    public String getPublicKey() {
        return publicKey;
    }

    public Interface resolve() {
        return new Interface.Builder()
                .parseAddresses(addresses)
                .parseDnsServers(dnsServers)
                .addExcludedApplications(excludedApplications)
                .parseListenPort(listenPort)
                .parseMtu(mtu)
                .parsePrivateKey(privateKey)
                .build();
    }

    public void setAddresses(final String addresses) {
        this.addresses = addresses;
        notifyPropertyChanged(BR.addresses);
    }

    public void setDnsServers(final String dnsServers) {
        this.dnsServers = dnsServers;
        notifyPropertyChanged(BR.dnsServers);
    }

    public void setListenPort(final String listenPort) {
        this.listenPort = listenPort;
        notifyPropertyChanged(BR.listenPort);
    }

    public void setMtu(final String mtu) {
        this.mtu = mtu;
        notifyPropertyChanged(BR.mtu);
    }

    public void setPrivateKey(final String privateKey) {
        this.privateKey = privateKey;
        try {
            publicKey = new KeyPair(Key.fromBase64(privateKey)).getPublicKey().toBase64();
        } catch (final IllegalArgumentException ignored) {
            publicKey = "";
        }
        notifyPropertyChanged(BR.privateKey);
        notifyPropertyChanged(BR.publicKey);
    }
}
