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
import requests
from Scan import CVE
from Scan import Services
import re
import json
from colorama import init, Fore, Style
init(autoreset=True)

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

def is_port_web(ip, port):
    if not check_port(ip, port):
        return False,''
    
    try:
        response = requests.get(f"http://{ip}:{port}", timeout=1)
        if response.status_code == 200:
            print(F"{Fore.RED} Pas de forcage https sur ce port \n")
            if not os.path.exists("Result_user/Port_"+str(port)+"/SSL"):
                os.mkdir("Result_user/Port_"+str(port)+"/SSL")
            with open('Result_user/Port_'+str(port)+'/SSL/vulnTLS.txt', 'w') as file:
                file.write("Pas de forcage https sur ce port")

            return True,'http'
    except requests.RequestException:
        pass
    
    try:
        response = requests.get(f"https://{ip}:{port}", timeout=1, verify=False)
        if response.status_code == 200:
            return True,'https'
    except requests.RequestException:
        pass
    
    return False,''

def extract_port(result,ip):
    ports = []
    print(result)
    lines = result.split("\n")
    for line in lines:
        match = re.match(r'^(\d+)/tcp', line)
        if match:
            ports.append(int(match.group(1)))

    # Affichez les ports trouvés
    if ports:
        print(f"Ports ouverts sur {ip}: {ports}")
    else:
        print(f"Aucun port ouvert trouvé sur {ip}.")
    return ports

def open_file(path):
    file_path = path
    with open(file_path, 'r') as file:
        # Lire le contenu du fichier
        content = file.read()
    return content

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
    print("""
  _____                                  _                              
 |  __ \                                (_)                             
 | |__) |___  ___ ___  _ __  _ __   __ _ _ ___ ___  __ _ _ __   ___ ___ 
 |  _  // _ \/ __/ _ \| '_ \| '_ \ / _` | / __/ __|/ _` | '_ \ / __/ _ 
 | | \ \  __/ (_| (_) | | | | | | | (_| | \__ \__ \ (_| | | | | (_|  __/
 |_|  \_\___|\___\___/|_| |_|_| |_|\__,_|_|___/___/\__,_|_| |_|\___\___|
                                                                        
                                                                        

    """)
    '''
    subdomains = input('Souhaitez vous faire un scan des sous-domaines ? \n Tapez 1 pour oui ou 0 pour non')
    if (subdomains == 1):
        try:
            response = requests.get(f"http://{ip}", timeout=1)
        
            if response.status_code == 200:
                command = ['wfuzz', '-u', 'http://'+ip, '-H', 'Host: FUZZ.'+ip, '-w' , 'wordlist/subdomains.txt', '--sc', '200']
                result = subprocess.check_output(command)
                print(result)

        except requests.RequestException:
            pass

        try:
            response = requests.get(f"https://{ip}", timeout=1)    
            if response.status_code == 200:
                command = ['wfuzz', '-u', 'https://'+ip, '-H', 'Host: FUZZ.'+ip, '-w' , 'wordlist/subdomains.txt', '--sc', '200']
                result = subprocess.check_output(command)
                print(result)
        except requests.RequestException:
            pass
    # Scan des ports
    print("Scan des ports...")
    print("")
    subprocess.call(["nmap", "-sV", "-p-", "-T4", "-oN", "Result_user/ports.txt", "--open", ip])
    result = open_file("Result_user/ports.txt")
    ports = extract_port(result,ip)
    print(ports)
 
    '''
    # Vérification Systeme d'exploitation
    ''''''
    #print("")
    #print("Vérification de l'OS...")
    #print("")
    #system = determine_os(ip)
    #print("")
    #print("OS utilisé : " + system)
    '''
    # Vérification port 80 et 443
    print("")
    print("Vérification des ports Web")
    print("")
    
    web_ports = []
    for i in range (len(ports)):
        port_result,value = is_port_web(ip, ports[i])
        if port_result == True:
            if (not os.path.exists("Result_user/Port_"+str(ports[i]))):
                os.mkdir("Result_user/Port_"+str(ports[i]))
            if (not os.path.exists("Result_traitement/Port_"+str(ports[i]))):
                os.mkdir("Result_traitement/Port_"+str(ports[i]))
            print(f"Port {ports[i]} ouvert")
            web_ports.append(ports[i])
            print("Scan des pages...")
            if value == 'https':
                results = subprocess.check_output(["wfuzz", "-c", "--hc", "404" ,"-o", "json","-w", "/usr/share/wordlists/dirb/common.txt","https://" + ip + ':'+str(ports[i])+"/FUZZ"])
                str_decoded = results.decode('utf-8')
                json_data = json.loads(str_decoded)
                with open('Result_traitement/Port_'+str(ports[i])+'/dir.json', 'w') as json_file:
                    json.dump(json_data, json_file, indent=4)  # indent=4 pour un formatage joli et lisible
                #subprocess.call(["dirb","https://"+ip,"-o","file.txt"])
                with open('Result_user/Port_'+str(ports[i])+'/dir.txt', 'w') as file:
                    file.write('Voici le résultat du scan de répertoire \n \n')
                    for obj in json_data:
                        url = obj['url']
                        code = obj['code']
                        file.write(str(url) + '    => ' + str(code))
                        if (str(code)[0] == '2'):
                            print(F"{str(url)}    =>  {Fore.GREEN}{str(code)}")
                        if (str(code)[0] == '3'):
                            print(F"{str(url)}    =>  {Fore.BLUE}{str(code)}")
                        if (str(code)[0] == '4'):
                            print(F"{str(url)}    =>  {Fore.RED}{str(code)}")
                        file.write('\n')
                        #print(obj)
            else:
                results = subprocess.check_output(["wfuzz", "-c", "--hc", "404" ,"-o", "json", "-w", "/usr/share/wordlists/dirb/common.txt","http://" + ip + ':'+str(ports[i])+"/FUZZ"])
                str_decoded = results.decode('utf-8')
                json_data = json.loads(str_decoded)
                with open('Result_traitement/Port_'+str(ports[i])+'/dir.json', 'w') as json_file:
                    json.dump(json_data, json_file, indent=4)  # indent=4 pour un formatage joli et lisible
                #subprocess.call(["dirb","http://"+ip,"-o","file.txt"])
                with open('Result_user/Port_'+str(ports[i])+'/dir.txt', 'w') as file:
                    file.write('Voici le résultat du scan de répertoire \n \n')
                    for obj in json_data:
                        url = obj['url']
                        code = obj['code']
                        file.write(str(url) + '    => ' + str(code))
                        if (str(code)[0] == '2'):
                            print(F"{str(url)}    =>  {Fore.GREEN}{str(code)}")
                        if (str(code)[0] == '3'):
                            print(F"{str(url)}    =>  {Fore.BLUE}{str(code)}")
                        if (str(code)[0] == '4'):
                            print(F"{str(url)}    =>  {Fore.RED}{str(code)}")
                        file.write('\n')
                        #print(obj)
                        
    
            CVE.main(ip,str(ports[i]))
            '''
    Services.main('http://' + ip,80)
    CVE.main(ip,str(80))

    