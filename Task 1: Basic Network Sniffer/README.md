# Basic Network Sniffer

## Objective
To build and run a simple Python based network sniffer that captures and analyzes packets, to understand network data flow and common protocols.

## Tools Used 
- Kali Linux (VMware)
- Windows 10 (Vmware) - as a remote host generating network activity.
- Scapy - for packet sniffing and decoding
- Python 3
- Wireshark - to display captured traffic 

## Implementation Steps ##
1. **Prerequisites**: 
    - Python 3.x
    - Administrator/root access to run the script, as raw sockets require elevated permissions.

2. **Setup**:
   - Created working directory:
     ```bash
     mkdir Sniffer_evidence
     ```
   - Navigate to the directory:
     ```bash
     cd Sniffer_evidence
     ```

3. **Run the script**:
   - Clone the repository or download the script:
     ```bash
     git clone https://github.com/yourusername/network-sniffer.git
     ```
