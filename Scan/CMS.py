'''

Détecter les CMS utilisés (Wordpress, Drupal ...)

Refaire un scan complet du site avec des scan spécialisés

Extraire tous les plugins, numéros de versions ou toute infirmations permettant de détécter des CVEs => injecter les résultats dans Services.py

Extraire les noms d'utilisateur 

Faire une liste blanche de CMS pour ensuite orienter l'analyse

Outils utilisés : 

- WPscan
- Dropscan
- joomscan
- CMSmap
- https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/wordpress
- https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/drupal
'''
import subprocess

def main(target, cms_type):
    if cms_type == "Joomla":
        cmd=['perl','/home/azureuser/joomscan/joomscan.pl','-u',target]
    elif cms_type == "Wordpress":
        cmd =['wpscan','--url',target]
    elif cms_type == "Drupal":
        cmd =['droopescan/droopescan','scan','drupal','-u',target]
    elif cms_type == "SilverStripe":
        cmd =['droopescan/droopescan','scan','silverstripe','-u',target]
    elif cms_type == "Moodle":
        cmd=['/home/azureuser/CMSmap/cmsmap.py',target]
    else :
        """This CMS is not supported, the cms supported are the following :
                - Wordpress
                - Joomla
                - Drupal
                - Moodle
                - SilverStripe
        """
        return 0
    subprocess.run(cmd, check=True)
    return 0
