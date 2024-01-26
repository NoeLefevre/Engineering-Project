'''

Récupération de tous les services associés à l'application Web

Si possible extraire les numéros de version

Comparer ensuite avec les versions actuelles pour détecter de pottentielles CVEs et POC publique

Faire bien 2 fonctions distinctes entre la récupération des services et la recherche de CVEs car cette dernière phase peur être réutiliser dans d'autres module (plugin CMS par ex)


Outils utilisés:
    whatwheb
    CMSeek
    github.com/gokulapap/wappalyzer-cli

'''

import subprocess
import json
import os
from Scan import CMS

#target = '192.168.1.77'

def clean(target,port):
    if os.path.exists('Result_traitement/Port_'+str(port)+'/Services/web.json'):
        try:
            os.remove('Result_traitement/Port_'+str(port)+'/Services/web.json')
        except OSError as e:
            print('cleaning before running crashed')

def main(target,port):
    print("""
     _    _ ___________  ______ _____ _____ _____ _   _ 
    | |  | |  ___| ___ \ | ___ \  ___/  __ \  _  | \ | |
    | |  | | |__ | |_/ / | |_/ / |__ | /  \/ | | |  \| |
    | |/\| |  __|| ___ \ |    /|  __|| |   | | | | . ` |
    \  /\  / |___| |_/ / | |\ \| |___| \__/\ \_/ / |\  |
     \/  \/\____/\____/  \_| \_\____/ \____/\___/\_| \_/
                                                    
    """)
    clean(target,port)
    cmd=['python3','CMSeeK/cmseek.py', '-u', target, '--batch']
    ip = target.replace("http://", "")
    cmd_temp = ["mv","CMSeeK/Result/" + ip + "/cms.json","Result_traitement/Port_"+str(port)+"/Services/"]
    subprocess.run(cmd_temp)
    resultpath = 'Result_traitement/Port_'+str(port) + '/Services/cms.json'
    logpath = '--log-json='+'Result_traitement/Port_'+str(port) + '/Services/web.json'

#####

    wappy_result_path = 'Result_traitement/Port_'+str(port) + '/Services/wappy.json'  # Chemin du fichier de sortie pour cmd3

#####

    cmd2 = ['whatweb',target,logpath]
    cmd3 = ['python3','wappalyzer-cli/src/wappy','-u',target]
    try:
        subprocess.run(cmd, check=True, stdout=subprocess.PIPE)
        subprocess.run(cmd2, check=True, stdout=subprocess.PIPE)

#####

        # Exécution de cmd3 et redirection de la sortie vers un fichier
        with open(wappy_result_path, 'w') as outfile:
            subprocess.run(cmd3, check=True, stdout=outfile)

#####

        f= open (resultpath,"r")
        data = json.loads(f.read())
        f= open ('Result_traitement/Port_'+str(port) + '/Services/web.json',"r")
        data2 = json.loads(f.read())

#####
        # Lecture et affichage des résultats de cmd3
      #  with open(wappy_result_path, 'r') as file:
      #      wappy_data = json.load(file)
      #      print("Résultats de Wappy pour la cible: " + target)
      #      print(json.dumps(wappy_data, indent=4))
#####
            #PS: ON PEUT AVOIR UN SOUCIS SI LA SORTIE DE WAPPY N'EST PAS AU FORMAT JSON (ERREUR DE PARSING)
            #PS2: ON PEUT AUSSI AVOIR UN SOUCIS SI WAPPY NE TROUVE RIEN (ERREUR DE PARSING AUSSI)
#####
            
        print('Targeting ' + str(data2[0]['target']))
        print("Os of the target : "+str(data2[0]['plugins']['HTTPServer']['os']))
        print("Using : "+str(data2[0]['plugins']['HTTPServer']['string']))
        services = str(data2[0]['plugins']['HTTPServer']['string'])
        services = services.strip("['']")
        services = services.split(" ")
        print(services)
        noms_services = []
        versions_services = []
        for service in services:
            if ('/' in service):
                nom, version = service.split("/")
                noms_services.append(nom)
                versions_services.append(version)

        with open('Result_user/Port_'+str(port)+'/Services/enum.txt', 'w') as file:
            file.write('Voici les services relevés : \n')
            for i in range (len(noms_services)):
                file.write(noms_services[i] + '  =>  ' + versions_services[i])
                file.write('\n')
        services_versions_dict = [{'service': nom, 'version': version} for nom, version in zip(noms_services, versions_services)]
        with open('Result_traitement/Port_'+str(port)+'/Services/enum.json', 'w') as fichier_json:
            json.dump(services_versions_dict, fichier_json, indent=4)
        subprocess.run(cmd2, check=True)
        if data['cms_name'] == '':
           print("No CMS found on this target")
        else:
           print("cms used : "+str(data['cms_name']))
           CMS.main(target,str(data['cms_name']))
    except subprocess.CalledProcessError as e:
        print('An error as occured \n' + str(e))