import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from scapy.all import sniff, ICMP, wrpcap

packet_count = 0
processed_packets = set()

def decrypt_chunk(encrypted_chunk, key):
    try:
        iv = encrypted_chunk[:16]
        ciphertext = encrypted_chunk[16:]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
        return unpadded_data
    except Exception as e:
        print(f"Error decrypting chunk: {e}")
        return None

def process_packet(packet, key, output_cap, output_txt):
    global packet_count
    if packet.haslayer(ICMP):
        icmp_packet = packet[ICMP]
        icmp_data = bytes(icmp_packet.payload)
        if icmp_data not in processed_packets:
            processed_packets.add(icmp_data)
            packet_count += 1
            decrypted_data = decrypt_chunk(icmp_data, key)
            if decrypted_data:
                print("Decrypted chunk:", decrypted_data.decode('utf-8'))
                with open(output_txt, 'ab') as f:
                    f.write(decrypted_data)
                wrpcap(output_cap, packet, append=True)

def main():
    if len(sys.argv) != 4:
        print("Usage: python script.py <key> <output_cap_file> <output_text_file>")
        sys.exit(1)

    key = sys.argv[1]
    output_cap = sys.argv[2]
    output_txt = sys.argv[3]

    if len(key) not in [16, 24, 32]:
        print("Error: Invalid key size. Key must be 16, 24, or 32 bytes long for AES.")
        sys.exit(1)

    print("Starting packet capture...")
    sniff(filter="icmp", prn=lambda x: process_packet(x, key.encode('utf-8'), output_cap, output_txt))
    print(f"Number of packets received: {packet_count}")

# Stylish banner for Ping Smuggler receiver script

banner = """

          $$\                            $$$$$$\                                              $$\                     
          \__|                          $$  __$$\                                             $$ |                    
 $$$$$$\  $$\ $$$$$$$\   $$$$$$\        $$ /  \__|$$$$$$\$$$$\  $$\   $$\  $$$$$$\   $$$$$$\  $$ | $$$$$$\   $$$$$$\  
$$  __$$\ $$ |$$  __$$\ $$  __$$\       \$$$$$$\  $$  _$$  _$$\ $$ |  $$ |$$  __$$\ $$  __$$\ $$ |$$  __$$\ $$  __$$\ 
$$ /  $$ |$$ |$$ |  $$ |$$ /  $$ |       \____$$\ $$ / $$ / $$ |$$ |  $$ |$$ /  $$ |$$ /  $$ |$$ |$$$$$$$$ |$$ |  \__|
$$ |  $$ |$$ |$$ |  $$ |$$ |  $$ |      $$\   $$ |$$ | $$ | $$ |$$ |  $$ |$$ |  $$ |$$ |  $$ |$$ |$$   ____|$$ |      
$$$$$$$  |$$ |$$ |  $$ |\$$$$$$$ |      \$$$$$$  |$$ | $$ | $$ |\$$$$$$  |\$$$$$$$ |\$$$$$$$ |$$ |\$$$$$$$\ $$ |      
$$  ____/ \__|\__|  \__| \____$$ |       \______/ \__| \__| \__| \______/  \____$$ | \____$$ |\__| \_______|\__|      
$$ |                    $$\   $$ |                                        $$\   $$ |$$\   $$ |                        
$$ |                    \$$$$$$  |                                        \$$$$$$  |\$$$$$$  |                        
\__|                     \______/                                          \______/  \______/                         


                    by 0x7sec
"""


if __name__ == "__main__":
    print(banner)
    main()
