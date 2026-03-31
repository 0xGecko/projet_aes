# Projet Cryptographie - Implémentation de l'AES en C 🔐

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

./aes [options] fichier_entree fichier_sortie

## 👤 Auteur
- Alexandre ACCIARI