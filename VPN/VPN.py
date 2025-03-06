import subprocess
import threading
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os
import time

class AESCipher:
    def __init__(self, key):
        self.key = key

    def encrypt(self, data):
        cipher = AES.new(self.key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return cipher.nonce, ciphertext, tag

    def decrypt(self, nonce, ciphertext, tag):
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
        data = cipher.decrypt_and_verify(ciphertext, tag)
        return data

class VPNClient:
    def __init__(self, config_file):
        self.config_file = config_file
        self.process = None
        self.lock = threading.Lock()

    def start_vpn(self):
        with self.lock:
            self.process = subprocess.Popen(
                ['openvpn', '--config', self.config_file],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            print("VPN baglantisi baslatildi.")

    def monitor_vpn(self):
        """VPN baglantisini izler ve kesildiginde yeniden baslatir."""
        while True:
            with self.lock:
                if self.process.poll() is not None:  # Baðlantý kesildi
                    print("VPN baglantisi kesildi. Yeniden baglaniyor...")
                    self.start_vpn()
            time.sleep(5)  # 5 saniyede bir durumu kontrol eder

    def stop_vpn(self):
        with self.lock:
            if self.process:
                self.process.terminate()
                self.process.wait()
                print("VPN baglantisi durduruldu.")

def main():
    # AES anahtarý oluþturma
    key = get_random_bytes(32)  # AES-256 için 32 bayt
    aes_cipher = AESCipher(key)

    # Þifreleme örneði
    data = 'Bu bir guvenli mesajdýr.'
    nonce, ciphertext, tag = aes_cipher.encrypt(data)
    print(f"Sifrelenmiþ veri: {ciphertext}")

    # VPN istemcisi baþlatma
    vpn_client = VPNClient('client.ovpn')  # OpenVPN yapýlandýrma dosyanýzýn adýný girin
    vpn_thread = threading.Thread(target=vpn_client.monitor_vpn, daemon=True)
    vpn_thread.start()

    try:
        # Þifre çözme iþlemi
        decrypted_data = aes_cipher.decrypt(nonce, ciphertext, tag)
        print(f"Cözülen veri: {decrypted_data}")

        # VPN baðlantýsýný sürekli izleme
        while True:
            time.sleep(1)  # Programýn devam etmesini saðlamak için bekleme

    except KeyboardInterrupt:
        print("\nProgram sonlandiriliyor...")
    finally:
        # Program sonlanýrken VPN baðlantýsýný kes
        vpn_client.stop_vpn()

if __name__ == "__main__":
    main()
