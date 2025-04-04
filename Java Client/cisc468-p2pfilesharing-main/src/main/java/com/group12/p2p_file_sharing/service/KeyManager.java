package com.group12.p2p_file_sharing.service;

import java.security.*;
import java.util.Base64;

import org.springframework.stereotype.Service;
import com.group12.p2p_file_sharing.crypto.RsaUtils;

import lombok.Getter;

@Service
public class KeyManager {
    @Getter
    private PrivateKey privateKey;
    @Getter
    private PublicKey publicKey;

    public KeyManager() throws NoSuchAlgorithmException {
        KeyPair pair = RsaUtils.generateKeyPair();
        this.privateKey = pair.getPrivate();
        this.publicKey = pair.getPublic();
    }

    public void setKeyPair(KeyPair newKeyPair) {
        this.privateKey = newKeyPair.getPrivate();
        this.publicKey = newKeyPair.getPublic();
    }


    public String getEncodedPublicKey() {
        return Base64.getEncoder().encodeToString(publicKey.getEncoded());
    }
}
