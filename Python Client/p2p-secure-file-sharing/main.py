# Dependencies: pip install zeroconf flask cryptography requests
from zeroconf import ServiceBrowser, ServiceInfo, Zeroconf
from flask import Flask, render_template_string, jsonify, request
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import secrets, hashlib, socket, threading, time, os, json, requests
import base64
from flask import send_file
from io import BytesIO
import traceback
from flask import make_response
from aes_utils import aes_encrypt


SERVICE_TYPE = "_p2p._tcp.local."
HTTP_PORT = 8000
SOCKET_PORT = 9000
AVAILABLE_FILES_DIR = "available_files"
KEY_FILE = "peer_key.pem"
AES_KEY_FILE = "aes_key.bin"

app = Flask(__name__)
os.makedirs(AVAILABLE_FILES_DIR, exist_ok=True)

@app.after_request
def apply_cors(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    return response

trusted_peers = {}
pending_requests = []
pending_connections = []

def get_peer_info(peer_name):
    if peer_name in listener.peers:
        return listener.peers[peer_name]
    fqdn = f"{peer_name}{SERVICE_TYPE}"
    return listener.peers.get(fqdn)


# Key management (unchanged)
def generate_keys():
    private_key = rsa.generate_private_key(65537, 2048)
    return private_key, private_key.public_key()

def save_private_key(private_key):
    with open(KEY_FILE, "wb") as f:
        f.write(private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))

def load_or_create_keys():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), None)
    else:
        private_key, _ = generate_keys()
        save_private_key(private_key)
    return private_key, private_key.public_key()

private_key, public_key = load_or_create_keys()

def load_or_generate_aes_key():
    if os.path.exists(AES_KEY_FILE):
        with open(AES_KEY_FILE, "rb") as f:
            return f.read()
    key = secrets.token_bytes(32)  # AES-256
    with open(AES_KEY_FILE, "wb") as f:
        f.write(key)
    return key

AES_KEY = load_or_generate_aes_key()

def get_fingerprint(pub_key):
    pub_bytes = pub_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    digest = hashes.Hash(hashes.SHA256())
    digest.update(pub_bytes)
    return digest.finalize().hex()

public_key_der = public_key.public_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
public_key_b64 = base64.b64encode(public_key_der).decode('utf-8')


# Trusted peers JSON management
def load_trusted_peers():
    if os.path.exists(TRUSTED_PEERS_FILE):
        with open(TRUSTED_PEERS_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_trusted_peers():
    with open(TRUSTED_PEERS_FILE, 'w') as f:
        json.dump(trusted_peers, f)

trusted_peers = load_trusted_peers()

# Zeroconf Discovery matching Java's jmdns logic
class PeerListener:
    def __init__(self, own_name):
        self.own_name = own_name
        self.peers = {}

    def remove_service(self, zeroconf, type, name):
        self.peers.pop(name, None)

    def add_service(self, zeroconf, type, name):
        if name == self.own_name:
            return

        info = zeroconf.get_service_info(type, name)
        if info:
            peer_ip = socket.inet_ntoa(info.addresses[0])
            peer_port = info.port
            peer_address = f"http://{peer_ip}:{peer_port}"

            if name not in self.peers:
                try:
                    pubkey = requests.get(f"{peer_address}/api/keys/public").text
                    files = requests.get(f"{peer_address}/api/files/list").json()
                    peer_files = [file_entry["name"] for file_entry in files]
                    #print(peer_files)

                    self.peers[name] = {
                        "ip": peer_ip,
                        "port": peer_port,
                        "fingerprint": pubkey,
                        "files": peer_files,
                        "online": True
                    }

                    if name not in trusted_peers:
                        pending_connections.append({
                            'name': name,
                            'ip': peer_ip,
                            'fingerprint': pubkey
                        })
                except Exception as e:
                    print(f"Error retrieving data from {peer_address}: {e}")

    def update_service(self, zeroconf, type, name):
        self.add_service(zeroconf, type, name)

# Flask routes to match Java endpoints
@app.route('/api/keys/public')
def api_public_key():
    return public_key_b64  # ✅ not the fingerprint





@app.route('/api/files/list')
def api_files_list():
    file_list = []
    for filename in os.listdir(AVAILABLE_FILES_DIR):
        filepath = os.path.join(AVAILABLE_FILES_DIR, filename)
        with open(filepath, 'rb') as file:
            file_data = file.read()
            sha256_hash = hashlib.sha256(file_data).digest()
            base64_hash = base64.b64encode(sha256_hash).decode('utf-8')

        file_entry = {
            "name": filename,
            "hash": base64_hash
        }
        file_list.append(file_entry)

    return jsonify(file_list)

@app.route('/request_receive_file', methods=['POST'])
def request_receive_file():
    data = request.json
    peer_name = data['peer']
    file_name = data['file']
    
    peer_info = get_peer_info(peer_name)
    if not peer_info:
        return jsonify({"error": "Peer not found"}), 404



    peer_address = f"http://{peer_info['ip']}:{peer_info['port']}/api/transfers/request"

    # Send the transfer request to Java-compatible API
    try:
        res = requests.get(peer_address, params={
            "type": "receive",
            "peerName": socket.gethostname(),
            "fileName": file_name
        })

        if res.status_code == 200:
            return jsonify({"message": "File request sent successfully!"}), 200
        else:
            return jsonify({"error": f"Error from peer: {res.text}"}), 500
    except Exception as e:
        print(f"Error sending request to peer: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/')
def index():
    return render_template_string('''
    <!doctype html>
    <html>
    <head>
        <title>P2P File Sharing</title>
        <link rel="stylesheet" href="{{ url_for('static', filename='style.css') }}">
        <script>
            async function fetchData(){
                const res = await fetch('/update');
                const data = await res.json();

                const peers = document.getElementById('peers');
                const local = document.getElementById('local_files');
                const remote = document.getElementById('peer_files');

                const selectedPeer = peers.value;
                const selectedLocal = local.value;
                const selectedRemote = remote.value;

                peers.innerHTML = data.peers.map(p => 
                    `<option value="${p.name}" ${p.name === selectedPeer ? 'selected' : ''}>
                        ${p.name} - ${p.ip} - 🔐 Secure communication established.
                    </option>`).join('');

                local.innerHTML = data.local_files.map(f => 
                    `<option ${f === selectedLocal ? 'selected' : ''}>${f}</option>`).join('');

                const current = data.peers.find(p => p.name === selectedPeer);
                const peerFiles = current?.files || [];

                remote.innerHTML = peerFiles.map(f => 
                    `<option ${f === selectedRemote ? 'selected' : ''}>${f}</option>`).join('');
            }

            async function fetchInbox(){
                const res = await fetch('/inbox');
                const data = await res.json();
                const box = document.getElementById('inbox');
                box.innerHTML = data.map((r, i) => {
                    const friendlyType = r.type === "send" ? "to receive" : "to send";
                    return `<p>[REQUEST] ${r.from} wants ${friendlyType} "${r.file}"<br>
                        <button onclick="approve(${i})" class="action-button">Accept</button> 
                        <button onclick="decline(${i})" class="action-button" style="background-color: var(--accent-color);">Decline</button>
                    </p>`;
                }).join('');
            }


            async function requestSendFile(){
                const peer = document.getElementById('peers').value;
                const file = document.getElementById('local_files').value;
                const res = await fetch('/request_send_file', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({peer, file})
                });
                alert((await res.json()).message);
            }

            async function requestReceiveFile(){
                const peer = document.getElementById('peers').value;
                const file = document.getElementById('peer_files').value;
                const res = await fetch('/request_receive_file', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({peer, file})
                });
                alert((await res.json()).message);
            }

            async function changeKey(){
                await fetch('/change_key', { method: 'POST' });
                alert("Key changed. Other peers will be notified shortly.");
            }

            async function approve(i){ await fetch(`/approve/${i}`, {method:'POST'}); fetchInbox(); }
            async function decline(i){ await fetch(`/decline/${i}`, {method:'POST'}); fetchInbox(); }

            setInterval(() => { fetchData(); fetchInbox(); }, 5000);
            window.onload = () => { fetchData(); fetchInbox(); };
        </script>
    </head>
    <body>
        <div class="service-card">
            <h2 style="color: var(--primary-color);">Available Peers</h2>
            <select id="peers"></select>
        </div>

        <div class="service-card">
            <h2 style="color: var(--primary-color);">Send File</h2>
            <select id="local_files"></select>
            <button onclick="requestSendFile()" class="action-button">Send File</button>
        </div>

        <div class="service-card">
            <h2 style="color: var(--primary-color);">Request File</h2>
            <select id="peer_files"></select>
            <button onclick="requestReceiveFile()" class="action-button">Request File</button>
        </div>

        <div class="service-card">
            <h2 style="color: var(--primary-color);">Pending Requests</h2>
            <div id="inbox"></div>
        </div>

        <div class="service-card">
            <h2 style="color: var(--primary-color);">Settings</h2>
            <button onclick="changeKey()" class="action-button">Change Key</button>
        </div>
    </body>
    </html>
    ''')


@app.route('/update')
def update():
    peer_list = []

    for name, data in listener.peers.items():
        peer_address = f"http://{data['ip']}:{data['port']}"
        try:
            # Refresh peer's file list from their HTTP API
            files = requests.get(f"{peer_address}/api/files/list", timeout=1).json()
            peer_files = [file_entry["name"] for file_entry in files]
            data['files'] = peer_files  # Update in-memory copy
        except Exception as e:
            print(f"[ERROR] Could not update files from {name}: {e}")
            data['files'] = []  # fallback

        peer_list.append({
            'name': name.replace(SERVICE_TYPE, ''),
            'ip': data['ip'],
            'fingerprint': data['fingerprint'],
            'files': data['files']
        })

    local_files = os.listdir(AVAILABLE_FILES_DIR)
    return jsonify(peers=peer_list, local_files=local_files)



# Socket server and file transfer (unchanged)
def encrypt_file(filepath):
    key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)
    with open(filepath, "rb") as f:
        data = f.read()
    digest = hashlib.sha256(data).hexdigest()
    encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend()).encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return {"key": key, "nonce": nonce, "tag": encryptor.tag, "ciphertext": ciphertext, "sha256": digest}

def start_message_listener(port=SOCKET_PORT):
    def handler():
        s = socket.socket()
        s.bind(('0.0.0.0', port))
        s.listen(5)
        print(f"Socket listening on port {port}")
        while True:
            conn, addr = s.accept()
            data = conn.recv(1024).decode()
            conn.sendall("RESPONSE: unknown".encode())
            conn.close()
    threading.Thread(target=handler, daemon=True).start()

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        return s.getsockname()[0]
    except:
        return "127.0.0.1"
    finally:
        s.close()

def publish_service(port=HTTP_PORT):
    zeroconf = Zeroconf()
    hostname = socket.gethostname()
    service_name = f"{hostname}.{SERVICE_TYPE}"

    info = ServiceInfo(
        SERVICE_TYPE, service_name,
        addresses=[socket.inet_aton(get_local_ip())],
        port=port,
        properties={"description": "Python Peer"}
    )

    zeroconf.register_service(info)
    return zeroconf, service_name

@app.route('/api/transfers/request', methods=['GET', 'OPTIONS'])
def handle_transfer_request():
    req_type = request.args.get('type')
    peer_name = request.args.get('peerName')
    file_name = request.args.get('fileName')


    if request.method == "OPTIONS":
        if req_type == "send":
            pending_requests.append({
                "type": "receive",
                "file": file_name,
                "from": peer_name
            })
        elif req_type == "receive":
            pending_requests.append({
                "type": "send",
                "file": file_name,
                "from": peer_name
            })
        return '', 200

    # Handle GETs
    if req_type == "send":
        pending_requests.append({
            "type": "receive",
            "file": file_name,
            "from": peer_name
        })
        return jsonify({"status": "receive request noted"}), 200

    elif req_type == "receive":
        pending_requests.append({
            "type": "send",
            "file": file_name,
            "from": peer_name
        })
        return jsonify({"status": "send request noted"}), 200

    return jsonify({"error": "Invalid request type"}), 400


# Java sends encrypted file here when peer approves the transfer request
@app.route('/api/transfers/receive', methods=['POST'])
def receive_file():
    file_name = request.args.get('fileName')
    encrypted_file_data = request.data
    try:
        decrypted_data = rsa_decrypt(encrypted_file_data)
        disk_data = aes_encrypt(decrypted_data)

        with open(os.path.join(AVAILABLE_FILES_DIR, file_name), "wb") as f:
            f.write(disk_data)

        return "<div class='toast success'>File successfully transferred</div>", 200
    except Exception as e:
        traceback.print_exc()
        return "<div class='toast error'>Error occurred</div>", 500
    
    
@app.route('/inbox')
def inbox():
    all_requests = [
        {
            "type": r["type"],
            "file": r["file"],
            "from": r["from"]
        }
        for r in pending_requests
    ]

    return jsonify(all_requests)

# Encrypt data with peer's RSA public key
def rsa_encrypt(data, peer_public_pem):
    public_key = serialization.load_pem_public_key(peer_public_pem.encode())
    encrypted = public_key.encrypt(
        data,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted

def rsa_encrypt_for_java(data, peer_public_key_b64):
    peer_public_key_der = base64.b64decode(peer_public_key_b64)
    peer_public_key = serialization.load_der_public_key(peer_public_key_der)
    encrypted = peer_public_key.encrypt(
        data,
        rsa_padding.PKCS1v15()
    )
    return encrypted



# Decrypt data with your own RSA private key
def rsa_decrypt(encrypted_data):
    return private_key.decrypt(
        encrypted_data,
        rsa_padding.PKCS1v15() 
    )


@app.route('/approve/<int:index>', methods=['POST'])
def approve(index):
    if index >= len(pending_requests):
        print("error: ", pending_requests)
        return jsonify({"error": "Invalid index"}), 404

    r = pending_requests.pop(index)
    if r["type"] == "send":  # Java wants to receive a file from Python
        peer_name = r["from"]
        file_name = r["file"]
        peer_info = listener.peers.get(f"{peer_name}.{SERVICE_TYPE}")

        if not peer_info:
            print("Peer not found:", peer_name)
            return jsonify({"error": "Peer not found"}), 404

        file_path = os.path.join(AVAILABLE_FILES_DIR, file_name)
        if not os.path.exists(file_path):
            print("File not found:", file_path)
            return jsonify({"error": "File not found"}), 404

        try:
            with open(file_path, "rb") as f:
                file_data = f.read()

            if file_data.startswith(b"AES1"):
                from aes_utils import aes_decrypt
                try:
                    file_data = aes_decrypt(file_data)
                    print(file_data)
                except Exception as e:
                    print(f"[ERROR] AES decryption failed for {file_name}: {e}")
                    return jsonify({"error": "Could not decrypt file"}), 500
                
            encrypted = rsa_encrypt_for_java(file_data, peer_info["fingerprint"])  # Using base64 DER key

            # Send directly to Java client at /api/transfers/receive
            receive_url = f"http://{peer_info['ip']}:{peer_info['port']}/api/transfers/receive"
            res = requests.post(
                receive_url,
                params={"fileName": file_name},
                data=encrypted,
                headers={"Content-Type": "application/octet-stream"}
            )

            if res.status_code == 200:
                print("File sent to Java successfully.")
                return jsonify({"message": "File sent successfully"}), 200
            else:
                print("Java responded with error:", res.status_code, res.text)
                return jsonify({"error": f"Java client error: {res.status_code} {res.text}"}), 500

        except Exception as e:
            print("[ERROR] Failed to send file to Java:")
            traceback.print_exc()
            return jsonify({"error": str(e)}), 500

    else:
        # Java wants to send a file to us (Python), so now we tell Java to send it
        peer_name = r["from"]
        file_name = r["file"]
        peer_info = listener.peers.get(f"{peer_name}.{SERVICE_TYPE}")

        if not peer_info:
            return jsonify({"error": "Peer not found"}), 404

        try:
            send_url = f"http://{peer_info['ip']}:{peer_info['port']}/api/transfers/send"
            res = requests.post(send_url, params={"peerName": socket.gethostname(), "fileName": file_name})

            if res.status_code == 200:
                return jsonify({"message": "File request accepted and Java is sending."}), 200
            else:
                return jsonify({"error": f"Java peer error: {res.status_code} {res.text}"}), 500

        except Exception as e:
            print("[ERROR] While triggering Java to send the file:", e)
            return jsonify({"error": str(e)}), 500



@app.route('/request_send_file', methods=['POST'])
def request_send_file():
    data = request.json
    peer_name = data['peer']
    file_name = data['file']
    
    peer_info = listener.peers.get(f"{peer_name}{SERVICE_TYPE}")
    if not peer_info:
        return jsonify({"error": "Peer not found"}), 404

    peer_address = f"http://{peer_info['ip']}:{peer_info['port']}/api/transfers/request"

    try:
        # Tell Java that Python wants to send it a file
        res = requests.get(peer_address, params={
            "type": "send",
            "peerName": socket.gethostname(),
            "fileName": file_name
        })

        if res.status_code == 200:
            print("Send request sent successfully!")
            return jsonify({"message": "Send request sent successfully!"}), 200
        else:
            return jsonify({"error": f"Error from Java peer: {res.status_code} {res.text}"}), 500

    except Exception as e:
        print("[ERROR] Failed to send 'send' request to Java peer:")
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

@app.route('/approve/<peer_name>', methods=['POST'])
def approve_from_java(peer_name):
    # Get the file from request.args
    file_name = request.args.get('fileName')
    print("SENDING: ", file_name)

    # Lookup peer and file
    peer_info = listener.peers.get(f"{peer_name}.{SERVICE_TYPE}")

    if not peer_info:
        return "Peer not found", 404

    file_path = os.path.join(AVAILABLE_FILES_DIR, file_name)
    if not os.path.exists(file_path):
        return "File not found", 404

    # Encrypt and send it to the Java peer
    with open(file_path, 'rb') as f:
        file_data = f.read()
        
        if file_data.startswith(b"AES1"):
            from aes_utils import aes_decrypt
            try:
                file_data = aes_decrypt(file_data)
            except Exception as e:
                print(f"[ERROR] AES decryption failed for {file_name}: {e}")
                return jsonify({"error": "Could not decrypt file"}), 500

    encrypted_file = rsa_encrypt_for_java(file_data, peer_info['fingerprint'])

    try:
        res = requests.post(
            f"http://{peer_info['ip']}:{peer_info['port']}/api/transfers/receive",
            params={"fileName": file_name},
            data=encrypted_file,
            headers={'Content-Type': 'application/octet-stream'}
        )
        return res.text, res.status_code
    except Exception as e:
        return f"Error sending file: {str(e)}", 500

@app.route('/decline/<int:index>', methods=['POST'])
def decline(index):
    if index >= len(pending_requests):
        print("Invalid decline index:", index)
        return jsonify({"error": "Invalid index"}), 404

    declined_request = pending_requests.pop(index)
    print(f"Declined request from {declined_request['from']} for file {declined_request['file']}")
    return jsonify({"message": "Request declined"}), 200

@app.route('/api/keys/update', methods=['POST'])
def key_update():
    data = request.json
    peer_name = data.get("peerName")
    new_pub_key_b64 = data.get("newKey")

    fqdn = f"{peer_name}{SERVICE_TYPE}"
    print(fqdn)
    print(listener.peers)
    if fqdn not in listener.peers:
        return jsonify({"error": "Unknown peer"}), 404

    listener.peers[fqdn]['fingerprint'] = new_pub_key_b64
    trusted_peers[fqdn] = new_pub_key_b64
    save_trusted_peers()

    print(f"[INFO] Public key updated for {fqdn}")
    return jsonify({"message": "Key updated successfully"}), 200

@app.route('/change_key', methods=['POST'])
def change_key():
    global private_key, public_key, public_key_b64

    private_key, public_key = generate_keys()
    save_private_key(private_key)

    public_key_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    public_key_b64 = base64.b64encode(public_key_der).decode('utf-8')

    # Notify trusted peers
    for peer_name, peer_data in listener.peers.items():
        notify_url = f"http://{peer_data['ip']}:{peer_data['port']}/api/keys/update"
        try:
            res = requests.post(notify_url, json={
                "peerName": socket.gethostname(),
                "newKey": public_key_b64
            })
            print(f"[KEY UPDATE] Sent to {peer_name}: {res.status_code}")
        except Exception as e:
            print(f"[ERROR] Could not notify {peer_name}: {e}")

    return jsonify({"message": "Key changed and peers notified"})

def encrypt_new_plaintext_files():
    while True:
        for f in os.listdir(AVAILABLE_FILES_DIR):
            path = os.path.join(AVAILABLE_FILES_DIR, f)
            try:
                with open(path, "rb") as file:
                    content = file.read()

                if content.startswith(b"AES1"):
                    continue  # already encrypted

                encrypted = aes_encrypt(content)
                with open(path, "wb") as out:
                    out.write(encrypted)
                print(f"[SECURE STORAGE] Encrypted manually added file: {f}")
            except Exception as e:
                print(f"[SECURE STORAGE ERROR] Skipping file {f}: {e}")
        time.sleep(5)


threading.Thread(target=encrypt_new_plaintext_files, daemon=True).start()

if __name__ == "__main__":
    start_message_listener()
    zeroconf, own_service_name = publish_service(HTTP_PORT)
    listener = PeerListener(own_service_name)
    browser = ServiceBrowser(zeroconf, SERVICE_TYPE, listener)
    threading.Thread(target=lambda: app.run('0.0.0.0', HTTP_PORT), daemon=True).start()

    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        zeroconf.close()
