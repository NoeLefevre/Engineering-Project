'''

Phase de reconnaissance élémentaire et très importante

- Liste des ports Web (ssh possiblement)
- Scan des pages
- Scan des sous domaines

Faire ce scan pour chaque sous-domaines trouvés

Ex d'outils à utiliser : 

- Nmap
- Dirb
- Gobuster
- Sublist3r.py

'''

import os
import subprocess
import socket

def check_port(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    try:
        sock.connect((ip, port))
        return True
    except socket.error:
        return False
    finally:
        sock.close()

def determine_os(ip):
    try:
        result = subprocess.check_output(["nmap", "-O", ip])
        result = result.decode('utf-8')  # decode from bytes to string
        if 'linux' in result.lower():
            print(f"La cible {ip} semble utiliser Linux.")
            system = "linux"
        elif 'windows' in result.lower():
            print(f"La cible {ip} semble utiliser Windows.")
            system = "windows"
        else:
            print(f"Il est impossible de déterminer l'OS de la cible {ip}. OS par défaut : Linux")
            system = "linux"
    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")
    return system

def main(ip):
    os.system("clear")
    print("""

    _____                                  _                              
    |  __ \                                (_)                             
    | |__) |___  ___ ___  _ __  _ __   __ _ _ ___ ___  __ _ _ __   ___ ___ 
    |  _  // _ \/ __/ _ \| '_ \| '_ \ / _` | / __/ __|/ _` | '_ \ / __/ _ \
    | | \ \  __/ (_| (_) | | | | | | | (_| | \__ \__ \ (_| | | | | (_|  __/
    |_|  \_\___|\___\___/|_| |_|_| |_|\__,_|_|___/___/\__,_|_| |_|\___\___|
                                                                            
                                                                            
    """)
    # Scan des ports
    print("Scan des ports...")
    print("")
    subprocess.call(["nmap", "-sV", "-p-", "-T4", "-oN", "ports.txt", "--open", ip])

    # Vérification Systeme d'exploitation
    print("")
    print("Vérification de l'OS...")
    print("")
    system = determine_os(ip)
    print("")
    print("OS utilisé : " + system)
    # Vérification port 80 et 443
    print("")
    print("Vérification des ports 80 et 443...")
    print("")
    if check_port(ip, 80):
        print("Port 80 ouvert")
        print("")
        print("Scan des pages...")
        subprocess.call(["gobuster", "dir", "-u", "http://" + ip, "-w", "/usr/share/wordlists/dirb/common.txt", "-o", "pages.txt"])
    else:
        print("Port 80 fermé")
    
    if check_port(ip, 443):
        print("Port 443 ouvert")
        print("")
        print("Scan des pages...")
        subprocess.call(["gobuster", "dir", "-u", "https://" + ip, "-w", "/usr/share/wordlists/dirb/common.txt", "-o", "pages.txt"])
    else:
        print("Port 443 fermé")


