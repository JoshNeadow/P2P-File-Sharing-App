# P2P-File-Sharing-App

This repository contains two peer-to-peer (P2P) file sharing clients:

- 🐍 A **Python client** using Flask, AES/RSA encryption, and Zeroconf for discovery
- ☕ A **Java client** using Spring Boot and JmDNS for mDNS discovery

These clients can discover each other over a local network, request file transfers, and securely exchange files using public key cryptography and encrypted local storage.

---
## 📦 Features

- 🌐 Peer discovery on a local network (mDNS)
- 🔐 Mutual authentication of contacts
- ✅ Consent-based file requests and transfers
- 📄 File listing without consent
- 🧾 File provenance verification from offline peers
- 🔁 Key migration and contact notification
- 🔒 Confidential and integrity-protected file transfers
- 🔑 Perfect forward secrecy
- 🗄️ Secure local file storage
- ⚠️ Error and security warning messages with test coverage

---
## 🚀 Getting Started

### 🔧 Requirements

**Python Client:**
- Python 3.8+
- `pip install -r requirements.txt`

**Java Client:**
- Java 17+
- Maven
- Spring Boot

### ▶️ Run the Python Client

```bash
cd python-client/P2P-SECURE-FILE-SHARING
pip install -r requirements.txt
python main.py

Visit http://localhost:8000 in your browser.
```

### ▶️ Run the Java Client
cd java-client/cisc468-p2pfilesharing-main
sudo mvn spring-boot:run -D spring-boot.run.profiles=primary