package com.group12.p2p_file_sharing.model;

import lombok.Getter;

public class TransferRequest {
    @Getter
    private String type;
    @Getter
    private String peer;
    @Getter
    private String fileName;

    public TransferRequest(String type, String peer, String fileName) {
        this.type = type;
        this.peer = peer;
        this.fileName = fileName;
    }
}
