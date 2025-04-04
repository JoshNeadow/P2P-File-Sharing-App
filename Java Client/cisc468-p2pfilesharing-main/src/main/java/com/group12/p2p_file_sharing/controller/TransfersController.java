package com.group12.p2p_file_sharing.controller;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.Socket;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.Map;
import java.util.HashMap;
import java.util.Base64;

import java.security.KeyPair;
import org.springframework.http.HttpStatus;


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
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;
import org.springframework.http.ResponseEntity;

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
    private final String thisPeerName;

    @Value("${file_directory:available-files}")
    private String FILE_DIR;

    public TransfersController(
        TransfersRepository transfersRepository,
        PeerRepository peerRepository,
        KeyManager keyManager,
        @Value("${peer.name}") String thisPeerName
    ) {
        this.transfersRepository = transfersRepository;
        this.peerRepository = peerRepository;
        this.keyManager = keyManager;
        this.thisPeerName = thisPeerName;
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
            try {
                // Step 1: Notify peer you want to send a file
                String notifyUrl = "http://" + peer.getHost() + ":" + peer.getPort()
                        + "/api/transfers/request?type=send&peerName=" + peerRepository.getOwnServiceId()
                        + "&fileName=" + fileName;

                restTemplate.getForObject(notifyUrl, String.class);

                // Step 2: Save the request locally so the user can click “Send” later from UI
                transfersRepository.addSendRequest(new TransferRequest(type, peerName, fileName));

                return "<div class='toast success'>Send request sent. Waiting for peer approval.</div>";

            } catch (Exception e) {
                e.printStackTrace();
                return "<div class='toast error'>Failed to send file request</div>";
            }
        }

        try {
            String peerAddress = "http://" + peer.getHost() + ":" + peer.getPort()
            + "/approve/" + peerRepository.getOwnServiceId();

            String res = restTemplate.postForObject(
                    peerAddress + "?type=send&peerName=" + peerRepository.getOwnServiceId() + "&fileName=" + fileName,
                    null,
                    String.class
            );

            transfersRepository.removeReceiveRequest(new TransferRequest(type, peerName, fileName));

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
            File outputFile = new File(FILE_DIR, "/" + fileName);
            try (FileOutputStream fos = new FileOutputStream(outputFile)) {
                fos.write(decryptedFile);
            }

            return "<div class='toast success'>File successfully transferred</div>";
        } catch (Exception e) {
            e.printStackTrace();
            return "<div class='toast error'>Error occurred</div>";
        }
    }

    @PostMapping("/send")
    @ResponseBody
    public String sendApprovedFile(@RequestParam String peerName, @RequestParam String fileName) {
        Peer peer = peerRepository.getPeerByName(peerName);

        File uploadDir = new File(FILE_DIR);
        File matchingFile = null;

        if (uploadDir.exists() && uploadDir.isDirectory()) {
            matchingFile = Arrays.stream(uploadDir.listFiles())
                    .filter(file -> file.getName().equals(fileName))
                    .findFirst()
                    .orElse(null);
        }

        if (matchingFile == null) {
            return "<div class='toast error'>File not found</div>";
        }

        try {
            PublicKey publicKey = RsaUtils.getPublicKeyFromBase64(peer.getPublicKey());
            byte[] encryptedFile = RsaUtils.encryptFile(matchingFile, publicKey);

            String peerAddress = "http://" + peer.getHost() + ":" + peer.getPort()
                    + "/api/transfers/receive?fileName=" + fileName;

            HttpEntity<byte[]> requestEntity = new HttpEntity<>(encryptedFile);
            String res = restTemplate.exchange(
                    peerAddress,
                    HttpMethod.POST,
                    requestEntity,
                    String.class).getBody();

            transfersRepository.removeSendRequest(new TransferRequest("send", peerName, fileName));

            return res;

        } catch (Exception e) {
            e.printStackTrace();
            return "<div class='toast error'>Failed to send file</div>";
        }
    }

}


