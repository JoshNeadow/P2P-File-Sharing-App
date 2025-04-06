package com.group12.p2p_file_sharing.controller;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.client.RestTemplate;
import com.group12.p2p_file_sharing.crypto.RsaUtils;
import com.group12.p2p_file_sharing.model.FileDesc;
import com.group12.p2p_file_sharing.model.Peer;
import com.group12.p2p_file_sharing.model.TransferRequest;
import com.group12.p2p_file_sharing.repository.PeerRepository;
import com.group12.p2p_file_sharing.repository.TransfersRepository;
import com.group12.p2p_file_sharing.service.KeyManager;

import org.springframework.ui.Model;

@Controller
@RequestMapping("/api/transfers")
public class TransfersController {
    PeerRepository peerRepository;
    TransfersRepository transfersRepository;
    KeyManager keyManager;
    private final RestTemplate restTemplate = new RestTemplate();

    private String userPassword;

    @Value("${file_directory:available-files}")
    private String FILE_DIR;

    public TransfersController(
            TransfersRepository transfersRepository,
            PeerRepository peerRepository,
            KeyManager keyManager) {
        this.transfersRepository = transfersRepository;
        this.peerRepository = peerRepository;
        this.keyManager = keyManager;
        this.userPassword = "";
    }

    // called by other peers
    @ResponseBody // doesn't return a view
    @GetMapping("/request")
    public void handleFileRequest(@RequestParam String type, @RequestParam String peerName,
            @RequestParam String fileName) {
        TransferRequest request = new TransferRequest(type, peerName, fileName);
        // peer wants to send a file to this machine
        if (request.getType().equals("send")) {
            this.transfersRepository.addReceiveRequest(request);
        }
        // peer is requesting to receive a file from this machine
        else {
            this.transfersRepository.addSendRequest(request);
        }
    }

    // web app will call this endpoint to get this machine's own pending requests
    @GetMapping("/list")
    public String getTransferRequests(@RequestParam String type, Model model) {
        if (type.equals("send")) {
            Set<TransferRequest> requests = transfersRepository.getSendRequests();
            model.addAttribute("requests", requests);
            return "fragments/send-requests-list :: send-requests-list";
        } else {
            Set<TransferRequest> requests = transfersRepository.getReceiveRequests();
            model.addAttribute("requests", requests);
            return "fragments/receive-requests-list :: receive-requests-list";
        }
    }

    // web app will call this endpoint to approve pending request on own machine
    @ResponseBody
    @PostMapping("/approve")
    public String approveTransferRequest(@RequestParam String type, @RequestParam String peerName,
            @RequestParam String fileName) {
        Peer peer = peerRepository.getPeerByName(peerName);
        if (type.equals("send")) {
            File uploadDir = new File(FILE_DIR);
            File matchingFile = null;

            if (uploadDir.exists() && uploadDir.isDirectory()) {
                matchingFile = Arrays.stream(uploadDir.listFiles())
                        .filter(file -> file.getName().equals(fileName))
                        .findFirst()
                        .orElse(null);
            }

            // matched file
            if (matchingFile != null) {
                try {
                    // convert stored Base64 key to PublicKey
                    PublicKey publicKey = RsaUtils.getPublicKeyFromBase64(peer.getPublicKey());

                    // decrypt AES-GCM local file
                    byte[] decryptedFile = decryptFile(matchingFile);

                    // String s = new String(decryptedFile, StandardCharsets.UTF_8);
                    // System.out.println(s);

                    // encrypt file with receiver's public RSA key
                    byte[] encryptedFile = RsaUtils.encryptFile(decryptedFile, publicKey);

                    String peerAddress = "http://" + peer.getHost() + ":" + peer.getPort()
                            + "/api/transfers/receive?fileName=" + fileName;

                    HttpEntity<byte[]> requestEntity = new HttpEntity<>(encryptedFile);
                    String res = restTemplate.exchange(
                            peerAddress,
                            HttpMethod.POST,
                            requestEntity,
                            String.class).getBody();

                    transfersRepository.removeSendRequest(fileName);
                    updatePeerFiles(peerName);

                    return res;

                } catch (Exception e) {
                    e.printStackTrace();
                }
            }

            return "some error";
        }

        try {
            String peerAddress = "http://" + peer.getHost() + ":" + peer.getPort()
                    + "/approve/" + peerRepository.getOwnServiceId();

            String res = restTemplate.postForObject(
                    peerAddress + "?type=send&peerName=" + peerRepository.getOwnServiceId() + "&fileName=" + fileName,
                    null,
                    String.class);

            transfersRepository.removeReceiveRequest(fileName);

            return res;
        } catch (Exception e) {
            e.printStackTrace();
            return "<div class='toast error'>Failed to approve incoming file</div>";
        }
    }

    private void updatePeerFiles(String peerName) {
        Peer peer = peerRepository.getPeerByName(peerName);
        List<FileDesc> files = restTemplate.exchange(
                "http://" + peer.getHost() + ":" + peer.getPort() + "/api/files/list",
                HttpMethod.GET,
                null,
                new ParameterizedTypeReference<List<FileDesc>>() {
                }).getBody();
        peer.setFiles(files);
    }

    @ResponseBody
    @PostMapping("/receive")
    public String receiveIncomingFile(
            @RequestParam String fileName, @RequestBody byte[] encryptedFile) {

        try {
            byte[] decryptedFile = RsaUtils.decryptFile(encryptedFile, keyManager.getPrivateKey());
            String trimmed = fileName.substring(0, fileName.length() - 4); // remove .bin

            File outputFile = new File(FILE_DIR, "/" + trimmed + ".bin");

            // === PARAMETERS ===
            int saltLength = 16;
            int ivLength = 12;
            int keyLength = 256;
            int iterations = 20_000;
            int tagLength = 128; // in bits, GCM standard tag size

            // === RANDOM SALT & IV ===
            SecureRandom random = new SecureRandom();
            byte[] salt = new byte[saltLength];
            byte[] iv = new byte[ivLength];
            random.nextBytes(salt);
            random.nextBytes(iv);

            // === PBKDF2 KEY DERIVATION ===
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(userPassword.toCharArray(), salt, iterations, keyLength);
            byte[] keyBytes = factory.generateSecret(spec).getEncoded();
            SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");

            // === ENCRYPTION ===
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(tagLength, iv);
            cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
            byte[] ciphertext = cipher.doFinal(decryptedFile); // includes the tag at the end

            // === WRITE TO FILE ===
            try (FileOutputStream out = new FileOutputStream(outputFile)) {
                out.write(salt); // 16 bytes
                out.write(iv); // 12 bytes
                out.write(ciphertext); // ciphertext + GCM tag
            }

            return "<div class='toast success'>File successfully transferred</div>";
        } catch (Exception e) {
            e.printStackTrace();
            return "<div class='toast error'>Error occurred</div>";
        }
    }

    @ResponseBody
    @PostMapping("/set-password")
    public String setUserPassword(@RequestParam String password) {
        this.userPassword = password;

        return "<div class='toast success'>Password successfully set</div>";
    }

    private byte[] decryptFile(File encryptedFile) throws Exception {
        int saltLength = 16; // bytes
        int ivLength = 12; // bytes
        int keyLength = 256; // bits
        int iterations = 20000;
        int tagLength = 128; // bits

        byte[] fileBytes = Files.readAllBytes(encryptedFile.toPath());

        // === Extract parts ===
        byte[] salt = Arrays.copyOfRange(fileBytes, 0, saltLength);
        byte[] iv = Arrays.copyOfRange(fileBytes, saltLength, saltLength + ivLength);
        byte[] ciphertext = Arrays.copyOfRange(fileBytes, saltLength + ivLength, fileBytes.length);

        // === Derive key with PBKDF2 ===
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(userPassword.toCharArray(), salt, iterations, keyLength);
        byte[] keyBytes = factory.generateSecret(spec).getEncoded();
        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");

        // === Decrypt with AES-GCM ===
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(tagLength, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);
        return cipher.doFinal(ciphertext); // returns decrypted bytes
    }
}
