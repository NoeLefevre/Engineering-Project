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

def reconnaissance(ip):
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


