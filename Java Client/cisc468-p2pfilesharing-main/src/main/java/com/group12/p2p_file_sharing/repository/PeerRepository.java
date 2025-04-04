package com.group12.p2p_file_sharing.repository;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.stereotype.Repository;

import com.group12.p2p_file_sharing.model.Peer;

import lombok.Getter;
import lombok.Setter;

@Repository
public class PeerRepository {
    @Getter
    @Setter
    private String ownServiceId; // peer name of this machine
    private final Map<String, Peer> discoveredPeers = new HashMap<>();

    public void addPeer(Peer peer) {
        discoveredPeers.put(peer.getName(), peer);
    }

    public Peer getPeerByName(String name) {
        return discoveredPeers.get(name);
    }

    public List<Peer> getAllPeers() {
        return new ArrayList<>(discoveredPeers.values());
    }
}
