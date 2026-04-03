# Ligne directive - Projet AES en C

## Phase 1 : Chiffrement de base (AES-128)
- [x] Créer les structures de données (État, clé).
- [x] Implémenter les transformations de base : 'SubBytes', 'ShiftRows', 'MixColumns', 'AddRoundKey'.
- [x] Implémenter la fonction d'expansion de clé (KeyExpansion).
- [ ] Assembler ces fonctions pour chiffrer **un seul bloc** avec une clé de 128 bits.

## Phase 2 : Déchiffrement de base
- [ ] Implémenter les transformations inverses : 'InvShiftRows', 'InvSubBytes', 'InvMixColumns'.# Projet Cryptographie - Implémentation de l'AES en C 🔐

## 🎯 Description du projet
Ce projet a pour but de réaliser une implémentation complète et fonctionelle de l'algorithme de chiffrement AES (Advanced Encryption Standard) en langage C, en se basant sur le standard officiel FIPS-197.

Il a été réalise dans le cadre du module "Crypto compléments" du M1 Mathématiques de l'information, cryptographie de l'Université de Rennes.

## ✨ Fonctionnalités requises
- [ ] Chiffrement d'un bloc de 128 bits avec une clé de 128 bits.
- [ ] Déchiffrement d'un bloc de 128 bits.
- [ ] Chiffrement et déchiffrement d'un fichier complet en mode ECB.
- [ ] Utilisation d'une clé par défaut (`0x000102030405060708090a0b0c0d0e0f`) ou d'une clé choisie par l'utilisateur.
- [ ] Script de test mesurant le temps de calcul pour 100 chiffrements du fichier `alice.sage`.

## 🚀 Fonctionnalités bonus (à venir)
- [ ] Support des clés de 192 et 256 bits.
- [ ] Implémentation d'autres modes d'opération (CBC, CFB, OFB, GCM).

## 🛠️ Compilation
Le projet utilise un `Makefile` pour faciliter la compilation. Pour compiler le programme, placez-vous à la racine du projet et tapez :
```bash
make
```

## 💻 Utilisation
(Cette section sera mis à jour une fois que les options de la ligne de commande seront définies dans le main.c)
```bash
./aes [options] fichier_entree fichier_sortie
```

## 👤 Auteur
- Alexandre ACCIARI
- [ ] Assembler ces fonctions pour déchiffrer **un seul bloc**.

## Phase 3 : Chiffrement de document (Mode ECB)
- [ ] Créer une fonction pour lire un fichier blocs par blocs de 16 octets.
- [ ] Implémenter le mode ECB pour chiffrer un document entier avec un clé 128 bits.
- [ ] Gérer le "padding" (le remplissage du dernier bloc s'il fait moins de 16 octets).

## Phase 4 : Tests et performances
- [ ] Écrire un script de test ou un programme dédié.
- [ ] Mesurer le temps de calcul pour chiffrer 100x le fichier 'alice.sage' en mode ECB avec la clé par défaut.

## Phase 5 : Documentation et compte-rendu
- [ ] Commenter le code de façon claire.
- [ ] Rédiger la notice d'utilisation.
- [ ] Décrire le fonctionnement de l'implémentation.
- [ ] Détailler les difficultés rencontrées et les solutions trouvées.

## Phase 6 : Extensions (bonus si j'ai le temps)
- [ ] Ajouter les mode CBC, CFB (ou OFB) et GCM.
- [ ] Supporter les clés de 192 et 256 bits.