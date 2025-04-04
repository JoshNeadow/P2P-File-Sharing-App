package com.group12.p2p_file_sharing.model;

import java.util.List;

import javax.jmdns.ServiceInfo;

import lombok.Getter;
import lombok.Setter;

public class Peer {
    @Getter
    private String name;
    @Getter
    private String host;
    @Getter
    private int port;
    @Getter
    @Setter
    private List<FileDesc> files;
    @Getter
    @Setter
    private boolean isOnline;
    @Getter
    @Setter
    private String publicKey;

    public Peer(ServiceInfo serviceInfo, String publicKey, List<FileDesc> files) {
        this.name = serviceInfo.getName();
        this.host = serviceInfo.getHostAddresses()[0];
        this.port = serviceInfo.getPort();
        this.publicKey = publicKey;
        this.files = files;
        this.isOnline = true;
    }
}
