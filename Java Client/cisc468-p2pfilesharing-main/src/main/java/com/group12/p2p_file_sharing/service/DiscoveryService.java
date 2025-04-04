package com.group12.p2p_file_sharing.service;

import javax.jmdns.JmDNS;
import javax.jmdns.ServiceInfo;
import javax.jmdns.ServiceListener;
import javax.jmdns.ServiceEvent;

import java.io.File;
import java.io.IOException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import com.group12.p2p_file_sharing.model.FileDesc;
import com.group12.p2p_file_sharing.model.Peer;
import com.group12.p2p_file_sharing.repository.PeerRepository;

import jakarta.annotation.PostConstruct;

@Service
public class DiscoveryService implements DisposableBean {
    private static final Logger logger = LoggerFactory.getLogger(DiscoveryService.class);
    private static final String SERVICE_TYPE = "_p2p._tcp.local.";

    private final PeerRepository peerStore;
    private final RestTemplate restTemplate = new RestTemplate();

    @Value("${server.port:8080}") // default to 8080 if not found
    private int servicePort;
    private final JmDNS jmdns;

    public DiscoveryService(PeerRepository peerStore)
            throws IOException {
        this.jmdns = createJmDNSWithInterfaceSelection();
        this.peerStore = peerStore;
        logger.info("mDNS initialized on {}", jmdns.getInetAddress());
    }

    private JmDNS createJmDNSWithInterfaceSelection() throws IOException {
        Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
        while (interfaces.hasMoreElements()) {
            NetworkInterface iface = interfaces.nextElement();
            if (iface.isLoopback() || !iface.isUp())
                continue;

            Enumeration<InetAddress> addresses = iface.getInetAddresses();
            while (addresses.hasMoreElements()) {
                InetAddress addr = addresses.nextElement();
                if (!addr.isLoopbackAddress() && addr instanceof Inet4Address) {
                    JmDNS instance = JmDNS.create(addr, "p2p-file-sharing"); // Bind to both address AND interface
                    logger.info("Bound to interface: {} ({})", iface.getDisplayName(), addr.getHostAddress());
                    return instance;
                }
            }
        }
        throw new IOException("No non-loopback IPv4 interface found");
    }

    @PostConstruct
    public void start() throws IOException {
        registerService();
        discoverServices();
    }

    @Override
    public void destroy() throws IOException {
        stop();
    }

    public void registerService() throws IOException {
        String serviceId = "java-p2pfileshare";
        peerStore.setOwnServiceId(serviceId);

        ServiceInfo serviceInfo = ServiceInfo.create(
                SERVICE_TYPE,
                serviceId,
                servicePort,
                "blah");

        jmdns.registerService(serviceInfo);
        logger.info("Service registered: {}", serviceInfo);
    }

    public void discoverServices() throws IOException {
        jmdns.addServiceListener(SERVICE_TYPE, new ServiceListener() {
            @Override
            public void serviceAdded(ServiceEvent event) {
                logger.info("Service added: {}", event.getName());
                jmdns.requestServiceInfo(event.getType(), event.getName());
            }

            @Override
            public void serviceRemoved(ServiceEvent event) {
                logger.info("Service removed: {}", event.getName());
                peerStore.getPeerByName(event.getName()).setOnline(false);
            }

            @Override
            public void serviceResolved(ServiceEvent event) {
                ServiceInfo info = event.getInfo();
                if (info == null || info.getHostAddresses() == null || info.getHostAddresses().length == 0) {
                    logger.warn("Invalid ServiceInfo received for {}", event.getName());
                    return;
                }

                if (info.getName().equals("java-p2pfileshare")) {
                    return;
                }

                // first time seeing service
                if (peerStore.getPeerByName(info.getName()) == null) {
                    logger.info("Service resolved: {} (Host: {}, Port: {})",
                            info.getQualifiedName(),
                            info.getHostAddresses()[0],
                            info.getPort());

                    String peerAddress = "http://" + info.getHostAddresses()[0] + ":" +
                            info.getPort();
                    String pubKey = getPeerPublicKey(info.getName(), peerAddress);
                    List<FileDesc> files = getPeerFiles(info.getName(), peerAddress);

                    peerStore.addPeer(new Peer(info, pubKey, files));
                }
            }
        });
    }

    private String getPeerPublicKey(String peerId, String peerAddress) {
        // get peer's public key
        String peerPublicKey = restTemplate.getForObject(
                peerAddress + "/api/keys/public",
                String.class);
        logger.info("Retrieved public key of {}: {}", peerId, peerPublicKey);

        return peerPublicKey;
    }

    private List<FileDesc> getPeerFiles(String peerId, String peerAddress) {
        // get peer's files
        List<FileDesc> files = restTemplate.exchange(
                peerAddress + "/api/files/list",
                HttpMethod.GET,
                null,
                new ParameterizedTypeReference<List<FileDesc>>() {
                }).getBody();
        logger.info("Retrieved files of {}: {}", peerId, files);

        return files;
    }

    public void stop() throws IOException {
        if (jmdns != null) {
            jmdns.close();
            logger.info("mDNS service stopped");
        }
    }
}
