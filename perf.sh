#! /bin/bash

# Petit script pour tester les performances de notre AES

echo "Lancement du test de performance (100 chiffrements de alice.sage)..."

# On boucle 100 fois
for i in {1..100}
do 
    # On appelle le programme en mode silencieux pour ne pas polluer l'écran
    ./aes -e data/clear/alice.sage data/encrypted/alice.enc > /dev/null
done

echo "Test de chiffrement terminé !"