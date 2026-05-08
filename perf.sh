#!/bin/bash

# Configuration des chemins
INPUT="data/clear/alice.txt"
OUTPUT="alice_perf.enc"

# 1. Vérification de la présence du programme
if [ ! -f "./aes" ]; then
    echo "Erreur : L'exécutable ./aes est introuvable. Lancez 'make all' d'abord."
    exit 1
fi

echo "========================================================="
echo "   🚀 DÉMARRAGE DU TEST DE PERFORMANCE (100 Itérations)"
echo "   Mode : AES-128 ECB (Clé par défaut)"
echo "========================================================="

# 3. La boucle de 100 chiffrements chronométrée
time for i in {1..100}; do
    ./aes -e -m ecb "$INPUT" "$OUTPUT" > /dev/null
done

echo "========================================================="
echo "   ✅ TEST TERMINÉ !"
echo "========================================================="

# Nettoyage optionnel du fichier chiffré de test
rm -f "$OUTPUT"