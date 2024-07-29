from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.all import sniff
from colorama import Fore, Back, Style

# Function to display the terms and conditions
def display_terms():
    print(Back.BLACK + Fore.YELLOW + "-----------Packet Sniffer-----------")
    terms = Fore.GREEN + """
    Terms and Conditions:

    1. This packet sniffer tool is provided for educational and informational purposes only.
    2. You agree not to use this tool for any illegal or unethical activities.
    3. The developers of this tool are not responsible for any misuse or damage caused by its usage.
    4. Use of this tool may be subject to local laws and regulations. It is your responsibility to ensure compliance.

    Do you accept these terms and conditions? (yes/no)
    """
    print(terms + Style.RESET_ALL)

# Function to prompt the user to accept the terms
def accept_terms():
    display_terms()
    choice = input().lower()
    return choice == "yes"

# Packet callback function
def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto

        log_data = f"{Back.BLACK}{Fore.RED}Source IP: {src_ip} --> Destination IP: {dst_ip} | Protocol: {proto}{Style.RESET_ALL}\n"

        if TCP in packet:
            payload = packet[TCP].payload
            log_data += f"{Fore.CYAN}TCP Payload: {payload}{Style.RESET_ALL}\n"
        elif UDP in packet:
            payload = packet[UDP].payload
            log_data += f"{Fore.BLUE}UDP Payload: {payload}{Style.RESET_ALL}\n"
        elif ICMP in packet:
            payload = packet[ICMP].payload
            log_data += f"{Fore.YELLOW}ICMP Payload: {payload}{Style.RESET_ALL}\n"

        print(log_data)  # Print to console

        with open("packet_log.txt", "a") as log_file:
            log_file.write(log_data + '\n')

        print("Packet logged.")

# Ask the user to accept the terms before starting packet sniffing
try:
    if accept_terms():
        print("Terms accepted. Starting packet sniffing...")
        print(Back.WHITE + Fore.BLACK + "Press Ctrl+C to stop." + Style.RESET_ALL)
        sniff(prn=packet_callback, filter="ip")
    else:
        print("Terms not accepted. Exiting.")
except KeyboardInterrupt:
    print("Packet sniffing interrupted by user. Exiting.")
except Exception as e:
    print(f"An error occurred: {e}")
