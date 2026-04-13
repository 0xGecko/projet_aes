# Ligne directive - Projet AES en C

## Phase 1 : Chiffrement de base (AES-128)
- [x] Créer les structures de données (État, clé).
- [x] Implémenter les transformations de base : 'SubBytes', 'ShiftRows', 'MixColumns', 'AddRoundKey'.
- [x] Implémenter la fonction d'expansion de clé (KeyExpansion).
- [x] Assembler ces fonctions pour chiffrer **un seul bloc** avec une clé de 128 bits.

## Phase 2 : Déchiffrement de base
- [x] Implémenter les transformations inverses : 'InvShiftRows', 'InvSubBytes', 'InvMixColumns'.
- [x] Assembler ces fonctions pour déchiffrer **un seul bloc**.

## Phase 3 : Chiffrement de document (Mode ECB)
- [x] Créer une fonction pour lire un fichier blocs par blocs de 16 octets.
- [x] Implémenter le mode ECB pour chiffrer un document entier avec un clé 128 bits.
- [x] Gérer le "padding" (le remplissage du dernier bloc s'il fait moins de 16 octets).

## Phase 4 : Tests et performances
- [x] Écrire un script de test ou un programme dédié.
- [x] Mesurer le temps de calcul pour chiffrer 100x le fichier 'alice.sage' en mode ECB avec la clé par défaut.

## Phase 5 : Documentation et compte-rendu
- [x] Commenter le code de façon claire.
- [ ] Rédiger la notice d'utilisation.
- [x] Décrire le fonctionnement de l'implémentation.
- [x] Détailler les difficultés rencontrées et les solutions trouvées.

## Phase 6 : Extensions (bonus si j'ai le temps)
- [ ] Ajouter les mode CBC, CFB (ou OFB) et GCM.
- [ ] Supporter les clés de 192 et 256 bits.