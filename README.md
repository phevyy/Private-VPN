# 🛡️ Secure VPN Wrapper with AES Encryption

This project is a Python-based security tool that integrates **AES-256 (GCM Mode)** encryption with an automated **OpenVPN** client manager. It is designed to establish a secure VPN connection using a `.ovpn` configuration file and manage the connection lifecycle (auto-reconnect) while demonstrating secure data encryption practices.

## 📝 Description

This application serves two main purposes:
1.  **VPN Management:** It wraps the `openvpn` command-line tool to start a VPN connection. It runs a background thread that monitors the connection status; if the VPN drops, the script automatically attempts to reconnect.
2.  **Data Encryption:** It implements the `AESCipher` class using the `PyCryptodome` library to encrypt and decrypt sensitive data using **AES-256 in GCM mode** (Galois/Counter Mode), ensuring both confidentiality and data integrity.

## 🚀 Features

* **AES-256 Encryption:** Uses the industry-standard AES algorithm with GCM mode for authenticated encryption.
* **Auto-Reconnect:** A dedicated monitor thread checks the VPN process status every 5 seconds and restarts it if it crashes or disconnects.
* **Threaded Architecture:** VPN management runs on a separate daemon thread, allowing the main application to perform encryption tasks simultaneously.
* **Subprocess Management:** Directly interacts with the system's OpenVPN binary.

## 📂 Project Structure

```text
.
├── vpn_manager.py       # Main Python script (The code provided)
└── client.ovpn          # OpenVPN configuration file (Required)
```

## 🛠️ Prerequisites
Before running the script, ensure you have the following installed:

1. Python 3.x

2. OpenVPN Software: The openvpn command must be accessible from your system's PATH.

  *Linux:* sudo apt install openvpn

  *Windows:* Install OpenVPN Connect/GUI and add it to Environment Variables.

3. Python Libraries:
```
pip install pycryptodome
```

## ⚙️ Configuration

1. Place your valid OpenVPN configuration file in the project directory.

2. Rename the configuration file to client.ovpn OR update the filename in the main() function:
```python
vpn_client = VPNClient('your_config_file.ovpn')
```

## 🚀 How to Run

Run the script with administrative privileges (often required to start network interfaces via OpenVPN):
**Linux / macOS:**
```bash
sudo python vpn_manager.py
```
**Windows:** Run your terminal (CMD or PowerShell) as **Administrator**, then:
```bash
python vpn_manager.py
```

## 💻 Code Usage Example
The script automatically performs a self-test of the encryption and starts the VPN. Here is the logic flow:
```python
# 1. Initialize Encryption
key = get_random_bytes(32)
cipher = AESCipher(key)

# 2. Encrypt Data
nonce, ciphertext, tag = cipher.encrypt(b"Secret Message")

# 3. Start VPN Manager (Background Thread)
vpn_client = VPNClient('client.ovpn')
vpn_thread = threading.Thread(target=vpn_client.monitor_vpn)
vpn_thread.start()

# 4. Decrypt Data
plaintext = cipher.decrypt(nonce, ciphertext, tag)
```

## ⚠️ Security Note

- This tool wraps the OpenVPN client; it requires a valid VPN server configuration to work.

- The AES key is generated randomly at runtime. For persistent storage, key management logic should be added.

## 📝 License
This project is open-source and intended for educational purposes.

### 📌 Important Notes

1.  **OpenCV vs. OpenVPN:** Although initially mentioned as OpenCV, the code utilizes **OpenVPN** (via `subprocess`) for network operations. There is no image processing (OpenCV) involved in this script; it is purely a network security tool.
2.  **Library Requirement:** The script uses the `Crypto` module. To resolve this dependency, you must install the **`pycryptodome`** library (as mentioned in the Prerequisites), not the deprecated `crypto` package.
3.  **Administrative Privileges:** Establishing a VPN connection modifies network interfaces. Therefore, this script requires **Root/Sudo** privileges on Linux or **Administrator** privileges on Windows to function correctly.
