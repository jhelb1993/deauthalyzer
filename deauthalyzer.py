import subprocess
import psutil
import argparse
import signal
import sys
import os
import time
import datetime
import threading
from termcolor import colored

print("\n")
print(colored("         ▄████▀▀█▄", 'green'))
print(colored("       ▄█████████████████▄▄▄", 'green'))
print(colored("     ▄█████.▼.▼.▼.▼.▼.▼▼▼▼", 'green'))
print(" ▒█  ▀▀▄ █▀▀ █▀▀█ █░░█ ▀▀█▀▀ █░░█ █▀▀█ █░░ █░░█ ▀▀█ █▀▀ █▀▀█ ")
print(" ▒█░▒  █ █▀▀ █▄▄█ █░░█ ░░█░░ █▀▀█ █▄▄█ █░░ █▄▄█ ▄▀░ █▀▀ █▄▄▀ ")
print("  █▄▄▀▀  ▀▀▀ ▀░░▀ ░▀▀▀ ░░▀░░ ▀░░▀ ▀░░▀ ▀▀▀ ▄▄▄█ ▀▀▀ ▀▀▀ ▀░▀▀")
print(colored("     ███████▄.▲.▲.▲.▲▲▲▲▲▲", 'green'))
print(colored("     ██████████████████▀▀▀    (v1)\n", 'green'))
print("                 A tool to monitor and log Wifi-Deauthentication attacks")
print("                                       ~By: Pranjal Goel (z0m31en7) ")
print("                                       ~Modded by Jan Helbling (jhelb1993)")

def check_root_privileges():
    if os.getuid() != 0:
        print(colored('\n[x] Need higher privileges, run as root!!!', 'red'))
        sys.exit()

def get_wifi_interfaces():
    interfaces = psutil.net_if_addrs()
    wifi_interfaces = []
    for interface, addresses in interfaces.items():
        if interface.startswith('wl'):
           wifi_interfaces.append(interface)

    return wifi_interfaces

def enable_monitor_mode(interface):
    command = ['ifconfig', interface, 'down']
    subprocess.run(command)
    subprocess.run(['iwconfig', interface, 'mode','monitor'])
    subprocess.run(['ifconfig', interface, 'up'])

def extract_mac_address(line):
    mac_index = line.find('SA:') + 4
    mac_address = line[mac_index:mac_index + 17]
    return mac_address

def animate_loading():
    while True:
        for symbol in '|/-\\':
            sys.stdout.write(f'\r{colored("[+] Monitoring deauth packets...", "yellow")} {symbol}')
            sys.stdout.flush()
            time.sleep(0.1)

def detect_deauth_attack(interface):
    enable_monitor_mode(interface)
    print(f'{colored("[+] Monitor mode enabled for interface", "green")} {colored(interface, "cyan")}.')
    command = ['tshark', '-i', interface, '-Y', 'wlan.fc.type_subtype == 0x0c']
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)

    def signal_handler(sig, frame):
        print('\nExiting...')
        disable_monitor_mode(interface)
        process.terminate()
        sys.exit()

    signal.signal(signal.SIGINT, signal_handler)

    loading_thread = threading.Thread(target=animate_loading)
    loading_thread.daemon = True
    loading_thread.start()

    try:
        for line in process.stdout:
            line = line.decode().strip()
            if line.startswith('Radio tap'):
                loading_thread.join()
                print(f'\n{colored("[!] Deauthentication attack detected!", "red")}')
                print(colored(line, "cyan"))
                mac_address = extract_mac_address(line)
                print(f'{colored("Source MAC address:", "green")} {colored(mac_address, "yellow")}')
                attack_details = [line, f'Source MAC address: {mac_address}']
                write_attack_details(attack_details)
                for _ in range(4):
                    next_line = process.stdout.readline().decode().strip()
                    print(next_line)
                    attack_details.append(next_line)
                    write_attack_details(attack_details)
                break
    except KeyboardInterrupt:
        print('\nExiting...')
    finally:
        disable_monitor_mode(interface)
        process.terminate()

def disable_monitor_mode(interface):
    subprocess.run(['ifconfig', interface, 'down'])
    subprocess.run(['iwconfig', interface, 'mode', 'managed'])
    subprocess.run(['ifconfig', interface, 'up'])

def write_attack_details(details):
    now = datetime.datetime.now()
    filename = f"deauthlog_{now.strftime('%Y%m%d%H%M%S')}.txt"
    with open(filename, 'a') as file:
        for detail in details:
            file.write(detail + '\n')

parser = argparse.ArgumentParser(description='Detect WiFi deauthentication attacks.')
parser.add_argument('-i', '--interface', dest='iface', help='WiFi Inteface')
args = parser.parse_args()

if not args.iface:
    print("Use -i or --interface [your_interface]")
    sys.exit(1)
# Check root privileges
check_root_privileges()

detect_deauth_attack(args.iface)
