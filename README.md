# WASP: WebAugmentedSecureProtocol

**WASP** is a high-performance, stealthy Layer 3 VPN protocol built from scratch in **C++23**. It encapsulates IP packets inside **WebSockets** (WSS), allowing traffic to mask itself as standard HTTPS web traffic, making it highly effective for bypassing restrictive firewalls and Deep Packet Inspection (DPI).

The project prioritizes **security**, **low overhead**, and **concurrency**, utilizing a custom binary wire format and a multi-threaded crypto worker pool to saturate modern network links.

---

## Features

*   **Stealth Transport:** Uses WebSockets (RFC 6455) for transport, blending in with standard web traffic (port 443/80 compatible).
*   **Modern Cryptography:**
    *   **Cipher:** AES-256-GCM (Authenticated Encryption).
    *   **Key Exchange:** X25519 (Elliptic Curve Diffie-Hellman).
    *   **KDF:** HKDF-SHA256 for secure session key derivation.
*   **High Performance:**
    *   **Multi-threaded Architecture:** Decouples Network I/O (Libwebsockets) from Crypto operations (Worker Pool).
    *   **Zero-Copy Design:** Minimizes memory allocations in the hot path.
*   **Cross-Platform:** Native support for **Linux** (TUN) and **macOS** (UTUN).
*   **Automated Configuration:** The client and server automatically configure network interfaces and routing tables upon connection.

---

## The Protocol Specification

WASP operates in two phases: a text-based Handshake and a binary Transport phase.

### 1. The Wire Format (Binary Phase)
Once established, every WebSocket frame contains the following structure. All integers are Big-Endian.

```text
[Header (4 bytes)] [IV (12 bytes)] [Ciphertext (Variable)] [Auth Tag (16 bytes)]
```

*   **Header:** Contains Version (4 bits), Message Type (4 bits), and Session ID (3 bytes).
*   **IV:** Random 96-bit Initialization Vector (unique per packet).
*   **Ciphertext:** AES-256-GCM encrypted payload containing the IP packet + padding.
*   **Auth Tag:** GCM Integrity check.

### 2. The Handshake (Text Phase)
1.  **Client Hello:** Sends Ephemeral X25519 Public Key.
2.  **Server Hello:** Sends Server Public Key + Random Salt.
3.  **Key Derivation:** Both sides calculate `SharedSecret` via ECDH and derive `SessionKey` via HKDF.
4.  **Client Auth:** Client sends encrypted credentials (JSON).
5.  **Server Ready:** Server assigns a virtual IP and Session ID. Connection upgrades to Binary Mode.

---

## Build Prerequisites

You need a C++23 compliant compiler, CMake, OpenSSL, and Libwebsockets.

### macOS (Homebrew)
```bash
brew install cmake openssl@3 libwebsockets
```

### Linux (Debian/Ubuntu)
```bash
sudo apt update
sudo apt install cmake build-essential libssl-dev libwebsockets-dev pkg-config
```

---

## Compilation

```bash
# 1. Clone the repository
git clone https://github.com/yourname/WASP.git
cd WASP

# 2. Create build directory
mkdir build && cd build

# 3. Configure CMake (Release mode for performance)
cmake .. -DCMAKE_BUILD_TYPE=Release

# 4. Compile
make
```

> **Note for macOS:** If CMake cannot find OpenSSL, run:
> `cmake .. -DOPENSSL_ROOT_DIR=$(brew --prefix openssl@3)`

---

## Usage

WASP creates a virtual network on the `10.0.0.0/24` subnet.
*   **Server IP:** `10.0.0.1`
*   **Client IPs:** Assigned sequentially (e.g., `10.0.0.2`)

### 1. Start the Server
The server requires `sudo` to create the TUN interface and modify routing tables.

```bash
sudo ./wasp_vpn server
```
*Output: Starts listening on port 7681.*

### 2. Start the Client
Open a new terminal. Replace `127.0.0.1` with the server's real IP if running on different machines.

```bash
sudo ./wasp_vpn client 127.0.0.1
```
*Output: Connects, performs handshake, and auto-configures the interface.*

### 3. Verification
From the **Client** terminal, ping the server:

```bash
ping 10.0.0.1
```

If you see replies, the encrypted tunnel is fully operational.

---

# WASP Protocol Specification v1.0

## 1. Transport Layer
*   **Underlying Protocol:** WebSockets (RFC 6455).
*   **Port:** 443 (WSS) or 80 (WS).
*   **Frame Types:**
    *   **Text Frames:** Used exclusively for the Handshake (JSON).
    *   **Binary Frames:** Used exclusively for Encrypted Tunnel Data.

## 2. Cryptographic Primitives
All implementations must adhere to the following primitives:
*   **Key Exchange:** X25519 (Curve25519 ECDH).
*   **Key Derivation:** HKDF-SHA256 (Info: `"WASP_v1_KEY_GEN"`).
*   **Symmetric Encryption:** AES-256-GCM (Galois/Counter Mode).
*   **Byte Order:** Big-Endian (Network Byte Order) for all numeric fields.

---

## 3. The Handshake (Text Phase)

The handshake negotiates keys and configuration using JSON text frames.

### Step 1: Client Hello
The client generates an ephemeral X25519 keypair and sends its public key.

```json
{
  "type": "HELLO",
  "kex": "X25519",
  "pub": "<Base64 encoded 32-byte Client Public Key>"
}
```

### Step 2: Server Hello
The server generates an ephemeral X25519 keypair and a random 32-byte salt.

```json
{
  "type": "HELLO",
  "pub": "<Base64 encoded 32-byte Server Public Key>",
  "salt": "<Base64 encoded 32-byte Random Salt>"
}
```

**Key Derivation Point:**
At this stage, both parties compute the session key:
1.  `SharedSecret` = X25519(`MyPriv`, `PeerPub`)
2.  `SessionKey` = HKDF-SHA256(Input=`SharedSecret`, Salt=`Salt`, Info=`"WASP_v1_KEY_GEN"`)

### Step 3: Client Authentication
The client proves possession of the session key by encrypting a payload.

```json
{
  "type": "AUTH",
  "iv": "<Base64 encoded 12-byte IV>",
  "payload": "<Base64 encoded AES-GCM Ciphertext of credentials>"
}
```

### Step 4: Server Ready
If authentication succeeds, the server assigns a Session ID and a Virtual IP.

```json
{
  "type": "READY",
  "sid": "<Session ID Integer>",
  "assigned_ip": "10.0.0.X"
}
```

*State Transition:* Upon sending/receiving `READY`, both parties switch to **Binary Mode**.

---

## 4. The Packet Structure (Binary Phase)

Every binary WebSocket frame represents one WASP packet.

### 4.1. Outer Header (Cleartext)
Visible to the WebSocket layer. Used to route the packet to the correct decryption context.

```text
  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 | Ver | Type  |                 Session ID                      |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                                                               |
 +                  Initialization Vector (IV)                   +
 |                          (12 Bytes)                           |
 +                                                               +
 |                                                               |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

*   **Ver (4 bits):** Protocol Version. Currently `0x1`.
*   **Type (4 bits):** Message Type.
    *   `0x1`: DATA (IP Packet)
    *   `0x2`: CONTROL (Keepalive/Rekey)
*   **Session ID (24 bits):** Identifies the client session (assigned in Handshake Step 4).
*   **IV (96 bits):** Random Initialization Vector for AES-GCM. Must be unique per packet.

### 4.2. Encrypted Payload (Ciphertext)
This data follows the IV. It is encrypted using the derived `SessionKey`.

```text
  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |Cmd|          Original Length          |      IP Data ...      |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                       +
 |                                                               |
 +               ... IP Data ... (Variable Length)               +
 |                                                               |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                      Padding (Variable)                       |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

*   **Cmd (8 bits):** Inner Command.
    *   `0x1`: IPv4 Packet
    *   `0x2`: IPv6 Packet
*   **Original Length (16 bits):** The length of the actual IP data (excluding padding).
*   **IP Data:** The raw Layer 3 IP packet.
*   **Padding:** Random or zero bytes appended to align the payload (e.g., to 16-byte boundaries) or obfuscate traffic size.

### 4.3. Authentication Tag (Trailer)
The last 16 bytes of the WebSocket frame contain the GCM Auth Tag.

```text
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                   GCM Auth Tag (16 Bytes)                     |
 |                                                               |
 |                                                               |
 |                                                               |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

---

## 5. Packet Processing Flow

### Sending (Encryption)
1.  Read IP packet from TUN interface.
2.  Construct **Inner Payload**: `[Cmd] + [Length] + [IP Data] + [Padding]`.
3.  Generate random 12-byte **IV**.
4.  Encrypt **Inner Payload** using `AES-256-GCM(Key, IV)`.
5.  Construct **Outer Frame**: `[Header] + [IV] + [Ciphertext] + [Tag]`.
6.  Send as WebSocket Binary Frame.

### Receiving (Decryption)
1.  Read WebSocket Binary Frame.
2.  Parse **Outer Header**. Validate Version.
3.  Extract **Session ID** to locate the correct Session Key.
4.  Extract **IV**.
5.  Separate **Ciphertext** and **Tag** (last 16 bytes).
6.  Decrypt using `AES-256-GCM(Key, IV, Ciphertext, Tag)`.
    *   *If Tag check fails:* Drop connection immediately.
7.  Parse **Inner Payload**. Read `Original Length`.
8.  Extract `IP Data` based on length (discard padding).
9.  Write `IP Data` to TUN interface.

## Disclaimer

This project is a proof-of-concept VPN protocol developed for educational and research purposes. While it uses industry-standard cryptographic primitives (AES-GCM, Curve25519), it has not undergone a formal security audit. Use at your own risk.

**License:** MIT
