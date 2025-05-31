# Pwned_Packet

A basic but comprehensive command-line packet capturing tool built with Python and Scapy. It allows users to capture network traffic, filter by specific protocols, and save the results to a `.pcap` file for further analysis.

## Features

*   **Packet Capturing**: Captures live network traffic from your network interface.
*   **Protocol Filtering**: Allows users to specify a protocol (e.g., HTTP, DNS, TCP, UDP, ICMP, ARP, TLS/SSL, SSH, FTP, SMTP, etc.) to focus the capture.
*   **Custom Duration**: Set the duration for the packet capture.
*   **Save to PCAP**: Saves captured packets in the `.pcap` format, compatible with tools like Wireshark.
*   **Custom Save Location**: Specify the directory where the `.pcap` file should be saved.
*   **Colored Console Output**: Provides visually distinct console output for different types of information and packet details.
*   **User-Friendly CLI**: Interactive command-line interface for setting capture parameters.

## Prerequisites

*   Python 3.x
*   `pip` (Python package installer)
*   Root/Administrator privileges (required by Scapy for raw socket operations to capture packets).

## Installation

1.  **Clone the repository (or download the files):**
    ```bash
    git clone https://github.com/Silambaraselvan-15/Pwned_Packet.git 
    cd Pwned_Packet
    ```

2.  **Install dependencies:**
    It's recommended to use a virtual environment.
    ```bash
    python -m venv venv
    source venv/bin/activate  
    ```
    Install the required packages using the `requirements.txt` file:
    ```bash
    pip install -r requirements.txt
    ```
    The primary dependency is `scapy`.

## Usage

Run the main script from the project's root directory:

```bash
sudo python main.py
```
*(Note: `sudo` or administrator privileges are typically required for packet sniffing.)*

The script will then prompt you for:
1.  **Capture Duration**: How long (in seconds) you want to capture packets. Press Enter for the default duration.
2.  **Save Location**: The directory where the `Captured_Data.pcap` file will be saved. Press Enter for the default location (`capdata/`).
3.  **Filter Specific Protocol (Y/N)**: Choose 'Y' to filter for a specific protocol or 'N' to capture all traffic.
    *   If 'Y', you will be prompted to enter the **Protocol Name** (e.g., HTTP, DNS, TCP). A list of known protocols will be suggested.

After the capture duration or if an invalid protocol (that triggers termination) is specified, the captured packets will be saved, and the program will exit. You can also stop the capture prematurely with `Ctrl+C`.

## File Structure

```
Pwned_Packet/
├── main.py               # Main executable script, handles user interaction
├── SnifferCore.py        # Core packet sniffing and processing logic
├── PacketProcessor.py    # Handles formatting of packet data for display
├── Config.py             # Configuration (known ports, default values)
├── requirements.txt      # Python package dependencies
└── README.md             # This file
└── capdata/              # Default directory for saved .pcap files (created on first save)
```

## How it Works

1.  **User Input**: `main.py` collects capture parameters from the user.
2.  **Sniffing**: `SnifferCore.py` uses Scapy's `AsyncSniffer` to capture packets.
3.  **Callback Processing**: For each captured packet, a callback function in `SnifferCore.py` is invoked.
    *   If a specific protocol filter is active, it checks if the packet matches the filter.
    *   It identifies common protocols (TCP, UDP, ICMP, ARP, and various application layer protocols based on port numbers).
4.  **Formatting**: `PacketProcessor.py` (specifically the `StructResult` function) formats key information from the packet (MAC addresses, IP addresses) for display.
5.  **Output**: Identified packets and their details are printed to the console with color coding.
6.  **Saving**: After the sniffing session, all captured packets are saved to a `.pcap` file in the specified location.

---

