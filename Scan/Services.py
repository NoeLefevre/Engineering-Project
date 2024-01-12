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

#target = '192.168.1.77'

def clean(target):
    if os.path.exists('/home/azureuser/CMSeeK/Result/'+target+'/web.json'):
        try:
            os.remove('/home/azureuser/CMSeeK/Result/'+target+'/web.json')
        except OSError as e:
            print('cleaning before running crashed')

def main(target):
    print("""
     _    _ ___________  ______ _____ _____ _____ _   _ 
    | |  | |  ___| ___ \ | ___ \  ___/  __ \  _  | \ | |
    | |  | | |__ | |_/ / | |_/ / |__ | /  \/ | | |  \| |
    | |/\| |  __|| ___ \ |    /|  __|| |   | | | | . ` |
    \  /\  / |___| |_/ / | |\ \| |___| \__/\ \_/ / |\  |
     \/  \/\____/\____/  \_| \_\____/ \____/\___/\_| \_/
                                                    
    """)
    clean(target)
    cmd=['python3','/home/azureuser/CMSeeK/cmseek.py', '-u', target, '--batch']
    resultpath = '/home/azureuser/CMSeeK/Result/'+ target + '/cms.json'
    logpath = '--log-json='+'/home/azureuser/CMSeeK/Result/'+ target + '/web.json'

#####

    wappy_result_path = '/home/azureuser/CMSeeK/Result/' + target + '/wappy.json'  # Chemin du fichier de sortie pour cmd3

#####

    cmd2 = ['whatweb',target,logpath]
    cmd3 = ['python3','/home/azureuser/wappalyzer-cli/src/wappy','-u',target]
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
        f= open ('/home/azureuser/CMSeeK/Result/'+ target + '/web.json',"r")
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
        if data['cms_name'] == '':
            print("No CMS found on this target")
        else:
            print("cms used : "+str(data['cms_name']))
        subprocess.run(cmd2, check=True)
    except subprocess.CalledProcessError as e:
        print('An error as occured \n' + str(e))
