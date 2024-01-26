import requests
import subprocess
import json
import os
from colorama import init, Fore, Style
init(autoreset=True)

list_cpe_name = ['Apache','Tomcat','Nginx','Wordpress','Drupal','PHP']
list_cpe_values = ['cpe:2.3:a:apache:http_server:','cpe:2.3:a:apache:tomcat:','cpe:2.3:a:f5:nginx:','cpe:2.3:a:wordpress:wordpress:','cpe:2.3:a:drupal:drupal:','cpe:2.3:a:php:php:']

def Poc_exploitdb(idCve,file):
    commande2 = ["searchsploit", "--cve",idCve,"--www","--json"]
    result2 = subprocess.check_output(commande2)
    str_decoded = result2.decode('utf-8')
    json_data = json.loads(str_decoded)
    poc_data = json_data['RESULTS_EXPLOIT']
    file.write('CVE-'+idCve+' : \n')
    for k in range (len(poc_data)):
        url_poc = poc_data[k]['URL']
        poc_title = poc_data[k]['Title']
        file.write(poc_title +'   => ' + url_poc)
        file.write('\n')

def Poc_github(idCve,file,state):
    print('GITHUB')
    with open("CVE-"+idCve+"_export.json", 'r') as fichier:
            donnees = json.load(fichier)
    if (state == True):
        cve_id = donnees[0]["PoC_Data"]["pocs"][0]["name"]
        file.write('CVE-'+cve_id+' : \n')
    for i in range (len(donnees[0]["PoC_Data"]["pocs"])):
        cve_poc_url = donnees[0]["PoC_Data"]["pocs"][i]["html_url"]
        file.write(cve_poc_url)
        file.write('\n')


def recherche_cve(service, version,port):
    if (service in list_cpe_name):
        cpeIndex = list_cpe_name.index(service)
    cpe = list_cpe_values[cpeIndex]
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    query = f"?cpeName={cpe}{version}:*:*:*:*:*:*:*"
    url = base_url + query

    try:
        pocs = []
        response = requests.get(url)
        response.raise_for_status()
        # Analyse de la réponse
        data = response.json()
        #print(data)
        cve_items = data.get("vulnerabilities", [])
        #print(cve_items)
        if not cve_items:
            print("Aucun CVE trouvé pour ce service et cette version.")
        with open('Result_user/Port_'+port+'/CVEs/'+service+'.txt', 'w') as file:
            file.write('Voici scan des CVEs pour le service ' + service +' avec le numéro de version : ' + version)
            print('Voici scan des CVEs pour le service ' + service +' avec le numéro de version : ' + version)
            file.write('\n \n')
            m = 0
            poc_git = []
            poc_exploit = []
            for item in cve_items:
                temp = False
                m+=1
                cve = item.get("cve", {}).get("id", {})
                
                description = item.get("cve", {}).get("descriptions", {})
                criticity = item.get("cve", {}).get("metrics", {}).get("cvssMetricV31", {})
                file.write('Voici la ' + str(m) + 'eme CVE ')
                file.write('\n')
                file.write(f"CVE ID: {cve}, Description: {description}, Criticity : {criticity}")
                file.write('\n')
                cve_id = cve.replace("CVE-", "")
                commande = ["searchsploit", "--cve", cve_id,"--www"]
                file.write('Voici les POCs publiques extraits sur exploit db')
                file.write('\n')
                result = subprocess.run(commande, capture_output=True, text=True, check=True)
                file.write(result.stdout) 
                commande3 = ["python3","SploitScan/sploitscan.py","CVE-"+cve_id,"-e","json"]
                subprocess.run(commande3)
                with open("CVE-"+cve_id+"_export.json", 'r') as fichier:
                        donnees = json.load(fichier)
                if (len(donnees[0]["PoC_Data"]["pocs"])!=0):
                    cve_git = donnees[0]["PoC_Data"]["pocs"][0]["cve_id"]
                    cve_git = cve_git.replace("CVE-", "")
                    pocs.append(cve_git)
                    temp = True
                    poc_git.append(True)

                #print(len(result.stdout))
                if (len(result.stdout) != 63):
                    if (temp == False):
                        pocs.append(cve_id)
                        poc_git.append(False)
                        poc_exploit.append(True)
                    else:
                        poc_exploit.append(True)
                else:
                    if (temp == True):
                        poc_exploit.append(False)
                file.write('\n')
                #print(result.stdout) 
            print('Les CVEs sont toutes renseignées dans le fichier '+service+'.txt situé dans le répertoire Result_user puis dans le répertoire CVEs/')   
            print(f"Voici toutes les CVEs extraites contenant un POC publique pour le service {service} avec le numéro de version {version}\n")
            print('\n')
            with open('Result_user/Port_'+port+'/Pocs/'+service+'-poc.txt', 'w') as file:
                j = 0
                print(len(pocs))
                print(len(poc_git))
                print(len(poc_exploit))
                for idCve in pocs:

                    if (poc_git[j] == True and poc_exploit[j] == True):
                        Poc_exploitdb(idCve,file)
                        Poc_github(idCve,file,False)
                    elif(poc_git[j] == True):
                        Poc_github(idCve,file,True)
                    else:
                        Poc_exploitdb(idCve,file)
                    j+=1
                    #print('CVE-'+idCve+' : '+ poc_title +'   => ' + url_poc)
                print('\n')
                print("L'intégralité des POCs pour ce service sont renseignés dans le fichier " + service+"-poc.txt situé dans le répertoire Result_user/ puis dans le répertoire POCs/")    
                #print(pocs)
    except requests.RequestException as e:
        print(f"Erreur lors de la requête : {e}")

# Exemple d'utilisation

def main(ip,port):
    if not os.path.exists('Result_user/Port_'+port+'/CVEs'):
        os.mkdir('Result_user/Port_'+port+'/CVEs')
    if not os.path.exists('Result_user/Port_'+port+'/Pocs'):
        os.mkdir('Result_user/Port_'+port+'/Pocs')
    with open('Result_traitement/Port_'+str(port)+'/Services/enum.json', 'r') as fichier_json:
        services_versions_dict = json.load(fichier_json)
        noms_services = []
        versions_services = []
        for item in services_versions_dict:
            noms_services.append(item['service'])
            versions_services.append(item['version'])
        for i in range(len(noms_services)):
            recherche_cve(noms_services[i], versions_services[i],port)
    #recherche_cve('Apache', '2.4.6',port)

#recherche_cve('Apache', '2.4.1',str(80))
 
