package com.group12.p2p_file_sharing.repository;

import java.util.HashSet;
import java.util.Set;

import org.springframework.stereotype.Repository;

import com.group12.p2p_file_sharing.model.TransferRequest;

@Repository
public class TransfersRepository {
    private final Set<TransferRequest> pendingSends = new HashSet<>();
    private final Set<TransferRequest> pendingReceives = new HashSet<>();

    public Set<TransferRequest> getSendRequests() {
        return this.pendingSends;
    }

    public Set<TransferRequest> getReceiveRequests() {
        return this.pendingReceives;
    }

    public void addSendRequest(TransferRequest request) {
        pendingSends.add(request);
    }

    public void addReceiveRequest(TransferRequest request) {
        pendingReceives.add(request);
    }

    public void removeSendRequest(String fileName) {
        pendingSends.removeIf(request -> request.getFileName().equals(fileName));
    }

    public void removeReceiveRequest(String fileName) {
        pendingReceives.removeIf(request -> request.getFileName().equals(fileName));
    }

}
