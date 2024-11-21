import subprocess
from scapy.all import *
import os
from colorama import init, Fore, Style

# Initialize colorama
init()

def show_banner():
    banner = f"""
{Fore.RED}{Style.BRIGHT}
 _    _            _     _ 
| |  | |          | |   (_)
| |__| | __ _  ___| |__  _ 
|  __  |/ _` |/ __| '_ \| |
| |  | | (_| | (__| | | | |
|_|  |_|\__,_|\___|_| |_|_|
                          
{Style.RESET_ALL}
"""
    print(banner)

def list_network_adapters():
    result = subprocess.run(['iwconfig'], capture_output=True, text=True)
    lines = result.stdout.split('\n')
    adapters = [line.split()[0] for line in lines if 'IEEE' in line]
    return adapters

def scan_networks(interface, show_hidden):
    networks = []
    
    def packet_handler(packet):
        if packet.haslayer(Dot11Beacon):
            ssid = packet[Dot11Elt].info.decode(errors='ignore')
            bssid = packet[Dot11].addr2
            if ssid == '' and show_hidden:
                ssid = '<Hidden>'
            if {'ssid': ssid, 'bssid': bssid} not in networks:
                networks.append({'ssid': ssid, 'bssid': bssid})

    print(f"Scanning for networks on {interface}...")
    sniff(iface=interface, prn=packet_handler, timeout=10)

    print("Available networks:")
    for i, net in enumerate(networks):
        print(f"{i + 1}. SSID: {net['ssid']} | BSSID: {net['bssid']}")
    
    return networks

def capture_packets(interface, bssid):
    print(f"Capturing packets on {interface} for BSSID {bssid}...")
    subprocess.run(["airodump-ng", interface, "-w", "capture", "--output-format", "cap", "--bssid", bssid], check=True)

def create_wordlist():
    filename = input("Enter the filename for your wordlist: ")
    print("Enter words for the wordlist (type 'done' when finished):")
    with open(filename, 'w') as f:
        while True:
            word = input("> ")
            if word.lower() == 'done':
                break
            f.write(word + "\n")
    print(f"Wordlist saved as {filename}")

def generate_custom_input():
    length = int(input("Enter the length of the password to crack: "))
    use_uppercase = input("Include uppercase letters? (y/n): ").lower() == 'y'
    use_lowercase = input("Include lowercase letters? (y/n): ").lower() == 'y'
    use_digits = input("Include digits? (y/n): ").lower() == 'y'
    use_special = input("Include special characters? (y/n): ").lower() == 'y'

    charset = ''
    if use_uppercase:
        charset += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    if use_lowercase:
        charset += 'abcdefghijklmnopqrstuvwxyz'
    if use_digits:
        charset += '0123456789'
    if use_special:
        charset += '!@#$%^&*()-_=+[]{}|;:<>,.?/~`'

    return charset, length

def crack_password(cap_file, wordlist=None, use_gpu=False, custom_input=None, use_hashcat=False):
    if wordlist:
        if use_gpu:
            print(f"Cracking password using {wordlist} with Hashcat...")
            subprocess.run(["hashcat", "-m", "2500", cap_file, wordlist], check=True)
        else:
            print(f"Cracking password using {wordlist} with Aircrack-ng...")
            subprocess.run(["aircrack-ng", "-w", wordlist, cap_file], check=True)
    elif custom_input:
        charset, length = custom_input
        if use_hashcat:
            # Construct Hashcat mask based on user input
            hashcat_mask = '?1' * length
            hashcat_charsets = f'-1{charset}'

            print(f"Cracking password using custom input with Hashcat...")
            subprocess.run(["hashcat", "-m", "2500", hashcat_charsets, cap_file, hashcat_mask], check=True)
        else:
            print(f"Cracking password using custom input with Aircrack-ng...")
            wordlist_file = "custom_wordlist.txt"
            with open(wordlist_file, 'w') as f:
                for ch1 in charset:
                    for ch2 in charset:
                        for ch3 in charset:
                            # Continue this for the length of the password
                            if length == 3:
                                f.write(f"{ch1}{ch2}{ch3}\n")
                            # Add more nested loops for longer passwords

            subprocess.run(["aircrack-ng", "-w", wordlist_file, cap_file], check=True)

def install_tools():
V

   def main():
    show_banner()
    while True:
        print("\nMenu:")
        print("1. Install Required Tools")
        print("2. List Network Adapters")
        print("3. Scan Networks")
        print("4. Capture Packets")
        print("5. Create Wordlist")
        print("6. Crack Password (CPU)")
        print("7. Crack Password (GPU with Hashcat)")
        print("8. Crack Password Without Wordlist (Custom Input with Aircrack-ng)")
        print("9. Crack Password Without Wordlist (Custom Input with Hashcat)")
        print("10. Exit")
        
        choice = input("Enter your choice: ")
        
        if choice == "1":
            install_tools()
        
        elif choice == "2":
            adapters = list_network_adapters()
            if adapters:
                print("Available network adapters:")
                for i, adapter in enumerate(adapters):
                    print(f"{i + 1}. {adapter}")
            else:
                print("No network adapters found.")
        
        elif choice == "3":
            adapters = list_network_adapters()
            if adapters:
                print("Available network adapters:")
                for i, adapter in enumerate(adapters):
                    print(f"{i + 1}. {adapter}")

                adapter_choice = int(input("Select the network adapter to use (number): ")) - 1
                interface = adapters[adapter_choice]

                show_hidden_choice = input("Do you want to show hidden networks? (y/n): ").lower()
                show_hidden = (show_hidden_choice == 'y')

                networks = scan_networks(interface, show_hidden)
                
                if networks:
                    print("Scan completed.")
                else:
                    print("No networks found.")
            else:
                print("No network adapters found.")

        elif choice == "4":
            adapters = list_network_adapters()
            if adapters:
                print("Available network adapters:")
                for i, adapter in enumerate(adapters):
                    print(f"{i + 1}. {adapter}")

                adapter_choice = int(input("Select the network adapter to use (number): ")) - 1
                interface = adapters[adapter_choice]

                networks = scan_networks(interface, show_hidden=False)
                
                if networks:
                    for i, net in enumerate(networks):
                        print(f"{i + 1}. SSID: {net['ssid']} | BSSID: {net['bssid']}")

                    network_choice = int(input("Select the network to capture (number): ")) - 1
                    bssid = networks[network_choice]['bssid']
                    
                    capture_packets(interface, bssid)
                else:
                    print("No networks found.")
            else:
                print("No network adapters found.")

        elif choice == "5":
            create_wordlist()

        elif choice == "6":
            cap_file = "capture-01.cap"  # Default .cap file name
            wordlist = input("Enter the path to the wordlist file: ")
            crack_password(cap_file, wordlist, use_gpu=False)
        
        elif choice == "7":
            cap_file = "capture-01.cap"  # Default .cap file name
            wordlist = input("Enter the path to the wordlist file: ")
            crack_password(cap_file, wordlist, use_gpu=True)

        elif choice == "8":
            cap_file = "capture-01.cap"  # Default .cap file name
            charset, length = generate_custom_input()
            crack_password(cap_file, wordlist=None, use_gpu=False, custom_input=(charset, length))

        elif choice == "9":
            cap_file = "capture-01.cap"  # Default .cap file name
            charset, length = generate_custom_input()
            crack_password(cap_file, wordlist=None, use_gpu=True, custom_input=(charset, length), use_hashcat=True)

        elif choice == "10":
            print("Exiting...")
            break
        
        else:
            print("Invalid choice. Please try again.")

#