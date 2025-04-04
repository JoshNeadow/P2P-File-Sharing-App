package com.group12.p2p_file_sharing.controller;

import java.util.List;
import com.group12.p2p_file_sharing.model.FileDesc;
import java.io.File;
import java.util.List;
import java.util.ArrayList;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.Base64;


import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import com.group12.p2p_file_sharing.model.Peer;
import com.group12.p2p_file_sharing.repository.PeerRepository;
import com.group12.p2p_file_sharing.model.FileDesc;

@Controller
@RequestMapping("/api/peers")
public class PeerController {
    private PeerRepository peerStore;

    public PeerController(PeerRepository peerStore) {
        this.peerStore = peerStore;
    }

    @GetMapping
    public String getDiscoveredPeers(Model model) {
        List<Peer> peers = peerStore.getAllPeers();
        model.addAttribute("peers", peers);
        model.addAttribute("ownServiceId", peerStore.getOwnServiceId());

        // Fetch this machine's own files
        List<FileDesc> myFiles = getLocalFiles();
        model.addAttribute("myFiles", myFiles);

        return "fragments/peer-list :: peer-list";
    }

    private List<FileDesc> getLocalFiles() {
        List<FileDesc> fileList = new ArrayList<>();
        File dir = new File("available-files");

        if (dir.exists() && dir.isDirectory()) {
            for (File file : dir.listFiles()) {
                try {
                    byte[] bytes = java.nio.file.Files.readAllBytes(file.toPath());
                    String hash = java.util.Base64.getEncoder().encodeToString(
                            java.security.MessageDigest.getInstance("SHA-256").digest(bytes)
                    );
                    fileList.add(new FileDesc(file.getName(), hash));
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }

        return fileList;
    }

}
