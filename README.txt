# Traceroute

 ce programme présente une implémentation complète de la commande traceroute(tracert pour windows)
 avec ses options standard et un visualisateur graphique des chemins découverts.  

# Structure du code

le code source de ce programme se trouve totalement dans un seul fichier (traceroute.py) qui englobe deux
 class et une fonction et un bout de code pour faire la représentation graphique.

La class Result : pour construire les objets qui vont contenir les résultat d’une étape d’exploration d’un chemin


La class ResultTot : pour construire les objets qui vont contenir tout les donné d’un chemin
 trouvé(résultat d’exploration du chemin d’une adresse ip en entré)

La fonction traceroute : elle se charge d’explorer les chemin vers des destinations fournit en entré pour
 construire des objets représentatives qui stock les résultat de cette éxploration.


Le bout de code qui reste qui se présente sous forme de boule se charge de construire les graphes des chemins d’éxploration.  
