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
- [ ] Décrire le fonctionnement de l'implémentation.
- [ ] Détailler les difficultés rencontrées et les solutions trouvées.

## Phase 6 : Extensions (Les défis finaux)

**Objectif A : Flexibilité des tailles de clés (AES-192 et AES-256)**
- [x] Refactoriser le cœur (`aes.c` / `aes.h`) pour gérer dynamiquement le nombre de tours ($N_r = 10, 12$ ou $14$) et la taille de la clé en mots ($N_k = 4, 6$ ou $8$).
- [x] Modifier la fonction `KeyExpansion` pour intégrer la condition spéciale de l'AES-256 (ajout d'une étape `SubBytes` supplémentaire au milieu du processus).
- [x] Mettre à jour `main.c` pour accepter une nouvelle option (ex: `-s 256` ou `--size 256`) et adapter la longueur de la clé lue en argument.

**Objectif B : Modes opératoires classiques (CBC, CFB, OFB)**
- [x] Ajouter la gestion d'un Vecteur d'Initialisation (IV) de 16 octets via le terminal (ex: option `-v` ou `--iv`).
- [x] Implémenter le mode **CBC (Cipher Block Chaining)** : ajouter le XOR entre le texte clair et le bloc chiffré précédent.
- [ ] Implémenter le mode **CFB (Cipher Feedback)** : transformer l'AES en chiffrement par flot (stream cipher).
- [ ] Implémenter le mode **OFB (Output Feedback)**.

**Objectif C : Le "Boss final" - Mode GCM (Galois/Counter Mode)**
- [ ] Implémenter le mode **CTR (Counter Mode)** qui sert de base au GCM.
- [ ] Implémenter l'arithmétique dans le grand corps de Galois $GF(2^{128})$ pour créer la fonction d'authentification `GHASH`.
- [ ] Générer et vérifier le *Tag* d'authentification pour garantir l'intégrité des fichiers chiffrés.