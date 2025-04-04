package com.group12.p2p_file_sharing.controller;

import java.security.KeyPair;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import com.group12.p2p_file_sharing.crypto.RsaUtils;
import com.group12.p2p_file_sharing.model.Peer;
import com.group12.p2p_file_sharing.repository.PeerRepository;
import com.group12.p2p_file_sharing.service.KeyManager;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

@RestController
@RequestMapping("/api/keys")
public class KeyController {

    private final PeerRepository peerRepository;
    private final KeyManager keyManager;
    private final RestTemplate restTemplate = new RestTemplate();
    private final String thisPeerName;

    public KeyController(
        PeerRepository peerRepository,
        KeyManager keyManager,
        @Value("${peer.name}") String thisPeerName
    ) {
        this.peerRepository = peerRepository;
        this.keyManager = keyManager;
        this.thisPeerName = thisPeerName;
    }

    @PostMapping("/update")
    public ResponseEntity<String> updateKey(@RequestBody Map<String, String> payload) {
        String peerName = payload.get("peerName");
        String newKey = payload.get("newKey");

        Peer peer = peerRepository.getPeerByName(peerName);
        if (peer == null) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Peer not found");
        }

        peer.setPublicKey(newKey);
        System.out.println("[KEY UPDATE] Key updated for: " + peerName);

        return ResponseEntity.ok("Key updated");
    }

    @PostMapping("/rotate")
    @ResponseBody
    public String rotateKey() {
        try {
            KeyPair newPair = RsaUtils.generateKeyPair();
            keyManager.setKeyPair(newPair);

            String newKey = Base64.getEncoder().encodeToString(newPair.getPublic().getEncoded());
            notifyPeersOfKeyChange(newKey);

            return "<div class='toast success'>New key generated and shared.</div>";
        } catch (Exception e) {
            e.printStackTrace();
            return "<div class='toast error'>Failed to rotate key.</div>";
        }
    }

    private void notifyPeersOfKeyChange(String newBase64Key) {
        for (Peer peer : peerRepository.getAllPeers()) {
            String url = "http://" + peer.getHost() + ":" + peer.getPort() + "/api/keys/update";

            Map<String, String> body = new HashMap<>();
            body.put("peerName", thisPeerName);
            body.put("newKey", newBase64Key);

            try {
                restTemplate.postForEntity(url, body, String.class);
                System.out.println("[KEY NOTIFY] Updated " + peer.getName());
            } catch (Exception e) {
                System.out.println("[KEY ERROR] Could not update " + peer.getName());
                e.printStackTrace();
            }
        }
    }
}
