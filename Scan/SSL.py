import json
import os
import subprocess
def save_result(path,port):
    with open(path, 'r') as fichier:

        data = json.load(fichier)
        filtered_data = [item for item in data if item["severity"] not in ["OK", "INFO"]]
        print(filtered_data)
        chemin_fichier = 'Result_traitement/Port_'+port+'/SSL/vulnTLS.json'
    with open(chemin_fichier, 'a') as fichier:
        # Écriture des données JSON dans le fichier
        json.dump(filtered_data, fichier, indent=4)

def main(url,port):
    if not os.path.exists('Result_traitement/Port_'+str(80)+'/SSL'):
        os.mkdir('Result_traitement/Port_'+str(80)+'/SSL')
    commande = ['testssl','--jsonfile','Result_traitement/Port_'+str(80)+'/SSL/ssl.json','https://nestedflanders.htb']
    subprocess.run(commande)
    save_result("Result_traitement/Port_"+str(80)+"/SSL/ssl.json",str(80))