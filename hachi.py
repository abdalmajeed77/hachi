import subprocess
from scapy.all import *
import os
from colorama import init, Fore, Style
import time

# Initialize colorama
init()

# Language dictionaries for English, Arabic, and Hindi
languages = {
    'en': {
        'menu': "Menu:",
        'option_1': "1. Install Required Tools",
        'option_2': "2. List Network Adapters",
        'option_3': "3. Scan Networks",
        'option_4': "4. Capture Packets",
        'option_5': "5. Create Wordlist",
        'option_6': "6. Crack Password (CPU)",
        'option_7': "7. Crack Password (GPU with Hashcat)",
        'option_8': "8. Crack Password Without Wordlist (Custom Input with Aircrack-ng)",
        'option_9': "9. Crack Password Without Wordlist (Custom Input with Hashcat)",
        'option_10': "10. Exit",
        'invalid_choice': "Invalid choice. Please try again.",
        'exit_message': "Exiting...",
        'available_networks': "Available networks:",
        'scanning': "Scanning for networks...",
        'no_adapters': "No network adapters found.",
    },
    'ar': {
        'menu': "القائمة:",
        'option_1': "1. تثبيت الأدوات المطلوبة",
        'option_2': "2. عرض محولات الشبكة",
        'option_3': "3. فحص الشبكات",
        'option_4': "4. التقاط الحزم",
        'option_5': "5. إنشاء قائمة كلمات المرور",
        'option_6': "6. كسر كلمة المرور (CPU)",
        'option_7': "7. كسر كلمة المرور (GPU مع Hashcat)",
        'option_8': "8. كسر كلمة المرور بدون قائمة كلمات مرور (إدخال مخصص مع Aircrack-ng)",
        'option_9': "9. كسر كلمة المرور بدون قائمة كلمات مرور (إدخال مخصص مع Hashcat)",
        'option_10': "10. خروج",
        'invalid_choice': "اختيار غير صالح. حاول مرة اخرى.",
        'exit_message': "جارٍ الخروج...",
        'available_networks': "الشبكات المتاحة:",
        'scanning': "جارٍ فحص الشبكات...",
        'no_adapters': "لم يتم العثور على محولات شبكة.",
    },
    'hi': {
        'menu': "मेनू:",
        'option_1': "1. आवश्यक उपकरण स्थापित करें",
        'option_2': "2. नेटवर्क एडेप्टर सूचीबद्ध करें",
        'option_3': "3. नेटवर्क स्कैन करें",
        'option_4': "4. पैकेट कैप्चर करें",
        'option_5': "5. वर्डलिस्ट बनाएं",
        'option_6': "6. पासवर्ड क्रैक करें (CPU)",
        'option_7': "7. पासवर्ड क्रैक करें (GPU के साथ Hashcat)",
        'option_8': "8. बिना वर्डलिस्ट के पासवर्ड क्रैक करें (Aircrack-ng के साथ कस्टम इनपुट)",
        'option_9': "9. बिना वर्डलिस्ट के पासवर्ड क्रैक करें (Hashcat के साथ कस्टम इनपुट)",
        'option_10': "10. बाहर निकलें",
        'invalid_choice': "अमान्य विकल्प। कृपया पुन: प्रयास करें।",
        'exit_message': "बाहर निकल रहा है...",
        'available_networks': "उपलब्ध नेटवर्क:",
        'scanning': "नेटवर्क स्कैन किया जा रहा है...",
        'no_adapters': "कोई नेटवर्क एडेप्टर नहीं मिला।",
    }
}

# Function to show the banner
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

# Function to select language
def select_language():
    print("Select your language / اختر لغتك / अपनी भाषा चुनें:")
    print("1. English")
    print("2. العربية")
    print("3. हिंदी")
    
    lang_choice = input("Enter your choice (1/2/3): ")
    if lang_choice == '1':
        return 'en'
    elif lang_choice == '2':
        return 'ar'
    elif lang_choice == '3':
        return 'hi'
    else:
        print("Invalid choice, defaulting to English.")
        return 'en'

# Function to list network adapters
def list_network_adapters():
    result = subprocess.run(['iwconfig'], capture_output=True, text=True)
    lines = result.stdout.split('\n')
    adapters = [line.split()[0] for line in lines if 'IEEE' in line]
    return adapters

# Function to enable monitor mode on the interface
def enable_monitor_mode(interface):
    print(f"Enabling monitor mode on {interface}...")
    subprocess.run(["sudo", "ip", "link", "set", interface, "down"], check=True)
    subprocess.run(["sudo", "iw", interface, "set", "type", "monitor"], check=True)
    subprocess.run(["sudo", "ip", "link", "set", interface, "up"], check=True)

# Function to disable monitor mode on the interface
def disable_monitor_mode(interface):
    print(f"Disabling monitor mode on {interface}...")
    subprocess.run(["sudo", "ip", "link", "set", interface, "down"], check=True)
    subprocess.run(["sudo", "iw", interface, "set", "type", "managed"], check=True)
    subprocess.run(["sudo", "ip", "link", "set", interface, "up"], check=True)

# Function to scan networks with channel hopping
def scan_networks(interface, show_hidden=True):
    """
    Scans for available networks using the specified interface.

    Parameters:
        interface (str): The network interface in monitor mode.
        show_hidden (bool): Whether to include hidden networks in the results.

    Returns:
        list: A list of detected networks with SSID and BSSID.
    """
    enable_monitor_mode(interface)
    networks = {}

    def packet_handler(packet):
        if packet.haslayer(Dot11Beacon):
            ssid = packet[Dot11Elt].info.decode(errors='ignore') if packet[Dot11Elt].info else ''
            bssid = packet[Dot11].addr2
            channel = int(ord(packet[Dot11Elt:3].info)) if packet[Dot11Elt:3] else None
            if ssid == '' and not show_hidden:
                return
            networks[bssid] = {"SSID": ssid if ssid else "<Hidden>", "Channel": channel}

    print(f"Scanning for networks on {interface} (Press Ctrl+C to stop)...")

    try:
        # Channel hopping on common Wi-Fi channels (1, 6, 11)
        channels = [1, 6, 11]
        for channel in channels:
            os.system(f"sudo iw dev {interface} set channel {channel}")
            sniff(iface=interface, prn=packet_handler, timeout=5)

    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
    finally:
        disable_monitor_mode(interface)

    # Display networks
    if networks:
        print("\nDetected Networks:")
        print(f"{'No.':<5}{'SSID':<30}{'BSSID':<20}{'Channel':<10}")
        print("=" * 65)
        for idx, (bssid, data) in enumerate(networks.items(), start=1):
            print(f"{idx:<5}{data['SSID']:<30}{bssid:<20}{data['Channel']:<10}")
    else:
        print("\nNo networks detected.")
    
    return list(networks.values())

# Function to capture packets
def capture_packets(interface, bssid, lang_dict):
    print(f"Capturing packets on {interface} for BSSID {bssid}...")
    subprocess.run(["airodump-ng", interface, "-w", "capture", "--output-format", "cap", "--bssid", bssid], check=True)

# Function to create wordlist
def create_wordlist(lang_dict):
    filename = input("Enter the filename for your wordlist: ")
    print("Enter words for the wordlist (type 'done' when finished):")
    with open(filename, 'w') as f:
        while True:
            word = input("> ")
            if word.lower() == 'done':
                break
            f.write(word + "\n")
    print(f"Wordlist saved as {filename}")

# Function to generate custom input for password cracking
def generate_custom_input(lang_dict):
    length = int(input(lang_dict['enter_password_length']))
    use_uppercase = input(lang_dict['include_uppercase']).lower() == 'y'
    use_lowercase = input(lang_dict['include_lowercase']).lower() == 'y'
    use_digits = input(lang_dict['include_digits']).lower() == 'y'
    use_special = input(lang_dict['include_special']).lower() == 'y'

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

# Function to crack password using aircrack or hashcat
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
            subprocess.run(["aircrack-ng", "-w", wordlist_file, cap_file], check=True)

# Install tools
def install_tools():
    print("Installing required tools...")
    subprocess.run(['sudo', 'apt', 'install', 'aircrack-ng', 'hashcat', 'iwconfig'], check=True)

# Main function
def main():
    lang = select_language()
    lang_dict = languages[lang]
    
    show_banner()
    
    while True:
        print(f"\n{lang_dict['menu']}")
        print(lang_dict['option_1'])
        print(lang_dict['option_2'])
        print(lang_dict['option_3'])
        print(lang_dict['option_4'])
        print(lang_dict['option_5'])
        print(lang_dict['option_6'])
        print(lang_dict['option_7'])
        print(lang_dict['option_8'])
        print(lang_dict['option_9'])
        print(lang_dict['option_10'])

        choice = input("Select an option: ")
        
        if choice == '1':
            install_tools()
        elif choice == '2':
            adapters = list_network_adapters()
            if adapters:
                for adapter in adapters:
                    print(adapter)
            else:
                print(lang_dict['no_adapters'])
        elif choice == '3':
            adapters = list_network_adapters()
            if adapters:
                for i, adapter in enumerate(adapters):
                    print(f"{i + 1}. {adapter}")
                adapter_choice = int(input("Select an adapter by number: ")) - 1
                interface = adapters[adapter_choice]
                show_hidden = input("Show hidden networks? (y/n): ").lower() == 'y'
                scan_networks(interface, show_hidden, lang_dict)
            else:
                print(lang_dict['no_adapters'])
        elif choice == '4':
            print("Capture packets functionality not implemented yet.")
        elif choice == '5':
            create_wordlist(lang_dict)
        elif choice == '6':
            print("Cracking password (CPU) functionality not implemented yet.")
        elif choice == '7':
            print("Cracking password (GPU) functionality not implemented yet.")
        elif choice == '8':
            print("Cracking password without wordlist with Aircrack-ng not implemented yet.")
        elif choice == '9':
            print("Cracking password without wordlist with Hashcat not implemented yet.")
        elif choice == '10':
            print(lang_dict['exit_message'])
            break
        else:
            print(lang_dict['invalid_choice'])

if __name__ == "__main__":
    main()
