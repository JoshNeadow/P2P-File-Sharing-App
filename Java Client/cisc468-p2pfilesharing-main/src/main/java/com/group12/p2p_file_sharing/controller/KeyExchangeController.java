package com.group12.p2p_file_sharing.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.group12.p2p_file_sharing.service.KeyManager;

@RestController
@RequestMapping("/api/keys")
public class KeyExchangeController {

    private final KeyManager keyManager;

    public KeyExchangeController(KeyManager keyManager) {
        this.keyManager = keyManager;
    }

    // return this peer's public key
    @GetMapping("/public")
    public String getPublicKey() {
        return keyManager.getEncodedPublicKey();
    }
}
