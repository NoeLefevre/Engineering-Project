'''
Main de l'appli
Penser à comment le structurer
S'intéresser d'abord aux modules et ensuite le main de construira petit à petit
'''

# Imports
import os
import sys
from Scan import reconnaissance
from Scan import Services
from Exploitation import exploitation
from Elevation import elevation
# Accueil
print("""
      
  _____           _      _     _____           _            _   
 |  __ \         (_)    | |   |  __ \         | |          | |  
 | |__) | __ ___  _  ___| |_  | |__) |__ _ __ | |_ ___  ___| |_ 
 |  ___/ '__/ _ \| |/ _ \ __| |  ___/ _ \ '_ \| __/ _ \/ __| __|
 | |   | | | (_) | |  __/ |_  | |  |  __/ | | | ||  __/\__ \ |_ 
 |_|   |_|  \___/| |\___|\__| |_|   \___|_| |_|\__\___||___/\__|
                _/ |                                            
               |__/                                             

Par Hugo DAMOIS, Arnaud DUVAL, Noe LEFEVRE, Michael SOK et Sebastien WERNERT      
""")
while True:
    # Saisie adresse IP 
    ip = input("Saisir l'adresse IP cible : ")
    print("Adresse IP cible : ", ip)

    while True:
        print("""
        Veuillez choisir une option:
        1. Reconnaissance
        2. Exploitation
        3. Elevation de privilèges
        4. Quitter
        """)

        choice = input("Veuillez choisir votre option: ")

        if choice == '1':
            print("Option 1, Reconnaissance, chargement du module...") 
            print("")
            reconnaissance.main(ip)
            Services.main(ip)
            CMS.main(ip)
        elif choice == '2':
            print("Option 2, Exploitation, chargement du module...")
            exploitation.main(ip)
        elif choice == '3':
            print("Option 3, Elevation de privilèges, chargement du module...")
            elevation.main(ip)
        elif choice == '4':
            print("Fermeture du programme")
            break
        else:
            print("Choix invalide veuillez recommencer")
    
