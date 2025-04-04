package com.group12.p2p_file_sharing.controller;

import java.util.List;

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

import com.group12.p2p_file_sharing.model.Peer;
import com.group12.p2p_file_sharing.repository.PeerRepository;

@Controller
public class WebController {
    private PeerRepository peerStore;
    private FileController fileController;

    public WebController(PeerRepository peerStore, FileController fileController) {
        this.peerStore = peerStore;
        this.fileController = fileController;
    }

    @GetMapping("/")
    public String index() {
        return "index.html";
    }
}
