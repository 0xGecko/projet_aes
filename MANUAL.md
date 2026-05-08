# Manuel d'utilisation - Moteur Cryptographique AES

## 1. Introduction
Ce programme en ligne de commande permet de chiffrer et de déchiffrer en utilisant l'algorithme AES (Advanced Encryption Standard). Il support des clés de 128, 192 et 256 bits, ainsi que plusieurs modes d'opérations classiques et avancés (dont le chiffrement authentifié GCM).

## 2. Compilation
Le projet utilise un fichier `Makefile`. Pour compiler l'éxecutable optimisé, ouvrez votre terminal à la racine du projet et exécuter :
`make clean && make all`

## 3. Syntaxe générale
`./aes [OPTIONS] fichier_entree fichier_sortie`

## 4. Options disponibles
* `-e`, `--encrypt` : Action par défaut. Chiffre le `fichier_entree`.
* `-d`, `--decrypt` : Déchiffre le `fichier_entree`.
* `-s`, `--size`    : Définit la taille de la clé en bits. Valeurs acceptées : `128` (défaut), `192`, `256`.
* `-m`, `--mode`    : Définit le mode d'opération. Valeurs acceptées : `ecb` (défaut), `cbc`, `cfb`, `ofb`, `gcm`.
* `-k`, `--key`     : Clé secrète au format hexadécimal. Sa longueur doit correspondre à la taille choisie. Si omise, une clé par défaut peu sécurisée est utilisée.
* `-v`, `--iv`      : Vecteur d'initialisation (IV) au format héxadécimal (32 caractères recommandés). Indispensable pour les modes autres que ECB.
* `-h`, `--help`    : Affiche l'aide dans le terminal.

**Exemple 1 : Chiffrement simple en mode CBC (AES-128)**
`./aes -e -m cbc -k 000102030405060708090a0b0c0d0e0f -v aabbccddeeff00112233445566778899 document.txt document.enc`

**Exemple 2 : Chiffrement Authentifié GCM haute sécurité (AES-256)**
*Note : Le mode GCM authentifie l'intégralité du fichier et accole un Tag de sécurité à la fin du fichier de sortie.*
`./aes -e -s 256 -m gcm -k AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA -v BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB secret.txt secret_secure.enc`

**Exemple 3 : Déchiffrement GCM (Vérification d'intégrité)**
*Si le fichier a été altéré, le programme bloquera le déchiffrement et affichera une erreur critique.*
`./aes -d -s 256 -m gcm -k AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA -v BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB secret_secure.enc message_recupere.txt`