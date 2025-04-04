package com.group12.p2p_file_sharing.model;

import lombok.Getter;

public class FileDesc {
    @Getter
    private String name;
    @Getter
    private String hash;

    public FileDesc(String name, String hash) {
        this.name = name;
        this.hash = hash;
    }
}
