#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include "../include/aes.h"

// S-box : table de substitution pour le chiffrement AES
static const uint8_t sbox[256] = {
    // 0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

// S-box inverse : table de substitution pour le déchiffrement AES
static const uint8_t inv_sbox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

/* Tableau des constantes étendu pour supporter les 14 tours de l'AES-256 
On place 0x00 à l'indice 0 pour que rcon[1] corresponde bien au Round 1.
-----------
Remarque : 
Rcon est censé être un mot de 4 octets de type [x, 0, 0, 0], mais vu que seuls
les premiers octets changent, on ne stocke que ce premier octet en C (petite économie de place)
*/
static const uint8_t rcon[15] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d
};

/*
Fonction : init_state
---------------------
Initialise la matrice d'état (State) à partir du bloc de texte en clair (ou chiffré).
Conformément à la norme FIPS-197, le tableau d'entrée de 16 octets est copié
dans une matrice 4x4 en remplissant d'abord les colonnes (Column-major order).

Paramètres :
  - in    : Pointeur vers le tableau d'entrée (16 octets).
  - state : Matrice d'état 4x4 à initialiser.
*/
void init_state(const uint8_t in[16], state_t state) {
    // On parcout chaque colonne
    for (int c = 0; c < NB; c++) {
        // Pour chaque colonne, on parcourt chaque ligne
        for (int r = 0; r < 4; r++) {
            // On affecte la valeur correspondante depuis notre tableau d'entrée
            state[r][c] = in[r + 4*c];
        }
    }
}

/*
Fonction : print_state
----------------------
Fonction utilitaire de débogage.
Affiche la matrice d'état courante dans la console sous la forme d'une 
grille 4x4 en valeurs hexadécimales.
*/
void print_state(const state_t state) {
    for (int r = 0; r < 4; r++) {
        for (int c = 0; c < NB; c++) {
            // %02x affiche un nombre en héxadécimal (x) sur 2 caractères avec un 0 devant si besoin
            printf("%02x", state[r][c]);
        }
        printf("\n");
    }
    printf("\n");
}

/*
Fonction : sub_bytes
--------------------
Transformation non-linéaire.
Applique une substitution octet par octet sur la matrice d'état en utilisant 
une table de substitution (S-box). La S-box est construite par l'inverse 
multiplicatif dans le corps de Galois GF(2^8) suivi d'une transformation affine.
*/
void sub_bytes(state_t state) {
    // On parcourt chaque colonne
    for (int c = 0; c < NB; c++) {
        // On parcourt chaque ligne
        for (int r = 0; r < 4; r++) {
            // Remplacement de l'octet par sa valeur dans la S-box.
            state[r][c] = sbox[state[r][c]];
        }
    }
}

/*
Fonction : shift_rows
---------------------
Transformation linéaire de diffusion
Effectue un décalage circulaire des lignes de la matrice d'état vers la gauche.
L'objectif est de mélanger les octets de différentes colonnes.
 - Ligne 0 : Inchangée.
 - Ligne 1 : Décalage de 1 octet vers la gauche.
 - Ligne 2 : Décalage de 2 octets vers la gauche.
 - Ligne 3 : Décalage de 3 octets vers la gauche.
*/
void shift_rows(state_t state) {
    uint8_t temp;

    // Ligne 1 : Décalage de 1 vers la gauche
    temp = state[1][0];
    state[1][0] = state[1][1];
    state[1][1] = state[1][2];
    state[1][2] = state[1][3];
    state[1][3] = temp;

    // Ligne 2 : Décalage de 2 vers la gauche
    temp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;
    temp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp;

    // Ligne 3 : Décalage de 3 vers la gauche
    temp = state[3][3];
    state[3][3] = state[3][2];
    state[3][2] = state[3][1];
    state[3][1] = state[3][0];
    state[3][0] = temp;
}

/*
Fonction utilitaire : xtime
---------------------------
Opération fondamentale dans le corps fini de Galois GF(2^8).
Effectue la multiplication d'un polynôme par x (soit la valeur hexadécimale 0x02) 
modulo le polynôme irréductible P(x) = x^8 + x^4 + x^3 + x + 1 (0x11B).
Matériellement, cela se traduit par un décalage de bit vers la gauche, suivi
d'un XOR avec 0x1B en cas de dépassement de capacité (débordement du MSB).

Paramètre :
  - x : L'octet à multiplier par 0x02.
Retourne :
  - Le résultat de la multiplication dans GF(2^8).
*/
static uint8_t xtime(uint8_t x) {
    // Si le bit de poids fort est 1, on décale et on XOR avec 01xb
    // Sinon, on fait juste un décalage
    return (x & 0x80) ? (x << 1) ^ 0x1b : (x << 1);
}

/*
Fonction  : mix_columns
Transformation de diffusion sur les colonnes.
Traite chaque colonne de l'état comme un polynôme du troisième degré à 
coefficients dans GF(2^8). Chaque colonne est multipliée modulo x^4 + 1 
par un polynôme fixe c(x) = {03}x^3 + {01}x^2 + {01}x + {02}.
Cette étape garantit une forte diffusion au sein de l'algorithme.
*/
void mix_columns(state_t state) {
    uint8_t col[4];

    // On parcourt chaque colonne
    for (int c = 0; c < NB; c++) {
        // On sauvegarde la colonne d'origine car on va écraser les valeurs de 'state'
        for (int r = 0; r < 4; r++) {
            col[r] = state[r][c];
        }

        // On applique les calculs mathématiques (XOR et xtime)
        // Ligne 0 : (2 * c0) ^ (3 * c1) ^ (1 * c2) ^ (1 * c3)
        state[0][c] = xtime(col[0]) ^ (xtime(col[1]) ^ col[1]) ^ col[2] ^ col[3];

        // Ligne 1 : (1 * c0) ^ (2 * c1) ^ (3 * c2) ^ (1 * c3)
        state[1][c] = col[0] ^ xtime(col[1]) ^ (xtime(col[2]) ^ col[2]) ^ col[3];

        // Ligne 2 : (1 * c0) ^ (1 * c1) ^ (2 * c2) ^ (3 * c3)
        state[2][c] = col[0] ^ col[1] ^ xtime(col[2]) ^ (xtime(col[3]) ^ col[3]);

        // Ligne 3 : (3 * c0) ^ (1 * c1) ^ (1 * c2) ^ (2 * c3)
        state[3][c] = (xtime(col[0]) ^ col[0]) ^ col[1] ^ col[2] ^ xtime(col[3]);
    }
}

/*
Fonction : add_round_key
------------------------
Intégration de la clé secrète.
Effectue un XOR bit à bit entre la matrice d'état courante et la clé de tour 
calculée par l'expansion de clé.
*/
void add_round_key(state_t state, const uint8_t round_key[4][NB]) {
    // On parcourt chaque colonne 
    for (int c = 0; c < NB; c++) {
        // On parcourt chaque ligne
        for (int r = 0; r < 4; r++) {
            // On applique le XOR entre la case de l'État et la case de la clé
            state[r][c] ^= round_key[r][c];
        }
    }
}

/*
Fonction : key_expansion (MAJ)
------------------------------
Génération de la clé étendue.
Prend la clé maître (128, 192 ou 256 bits) et l'étend en un tableau de mots 
de 32 bits pour fournir une clé unique à chaque tour.
La fonction gère dynamiquement Nk et génère Nr + 1 clés de tour. 

Remarque (AES-256) : Si la clé initiale fait 256 bits (Nk = 8), une étape 
de substitution (SubWord) supplémentaire est appliquée à la moitié du bloc 
pour garantir une entropie suffisante.

Paramètres :
  - key      : Pointeur vers la clé maître.
  - w        : Tableau de destination pour la clé étendue.
  - key_size : Enumération définissant la taille de la clé (16, 24 ou 32 octets).
*/
void key_expansion(const uint8_t *key, uint8_t w[MAX_EXPANDED_KEY_WORDS][4], AES_KEY_SIZE key_size) {
        uint8_t temp[4];
        int NK = key_size / 4;          // Nombre de mots de la clé (4, 6 ou 8)
        int NR = NK + 6;                // Nombre de tours (10, 12 ou 14)
        int total_words = 4 * (NR + 1); // Taille totale de la clé étendue (44, 52 ou 60)

        // 1. Les NK premiers mots sont la clé d'origine
        for (int i = 0; i < NK; i++) {
            w[i][0] = key[4 * i];
            w[i][1] = key[4 * i + 1];
            w[i][2] = key[4 * i + 2];
            w[i][3] = key[4 * i + 3];
        }

        // 2. Calcul des mots suivants
        for (int i = NK; i < total_words; i++) {
            // On copie le mot précédent dans temp
            temp[0] = w[i - 1][0];
            temp[1] = w[i - 1][1];
            temp[2] = w[i - 1][2];
            temp[3] = w[i - 1][3];
            
            // Tous les NK mots, on applique RotWord, SubWord et Rcon
            if (i % NK == 0) {
                // Rotword : décalage cycle d'un octet vers la gauche
                uint8_t t = temp[0];
                temp[0] = temp[1];
                temp[1] = temp[2];
                temp[2] = temp[3];
                temp[3] = t;

                // Subword : on passe chaque octet dans la S-box
                temp[0] = sbox[temp[0]];
                temp[1] = sbox[temp[1]];
                temp[2] = sbox[temp[2]];
                temp[3] = sbox[temp[3]];

                // XOR avec la constante de Round (Rcon) sur le premier octet
                temp[0] ^= rcon[i / NK];
            } 

            // RÈGLE SPÉCIALE AES-256 : Subword supplémentaire si la clé fait 256 bits (NK > 6)
            else if (NK > 6 && i % NK == 4) {
                temp[0] = sbox[temp[0]];
                temp[1] = sbox[temp[1]];
                temp[2] = sbox[temp[2]];
                temp[3] = sbox[temp[3]];
            }

            // 3. XOR avec le mot NK crans en arrière
            w[i][0] = w[i - 4][0] ^ temp[0];
            w[i][1] = w[i - 4][1] ^ temp[1];
            w[i][2] = w[i - 4][2] ^ temp[2];
            w[i][3] = w[i - 4][3] ^ temp[3];
        }
}

/*
Fonction : aes_cipher (MAJ)
---------------------------
Moteur principal de chiffrement AES.
Orchestre les opérations cryptographiques pour chiffrer un bloc de 16 octets.
Le nombre de tours (NR) s'adapte dynamiquement (10, 12 ou 14) en fonction 
de la taille de la clé fournie.

Paramètres :
    - in       : Bloc de texte en clair (16 octets).
    - key      : Clé de chiffrement maître.
    - out      : Bloc de texte chiffré généré (16 octets).
    - key_size : Taille de la clé maître.
*/
void aes_cipher(const uint8_t in[16], const uint8_t *key, uint8_t out[16], AES_KEY_SIZE key_size) {
    state_t state;
    uint8_t w[MAX_EXPANDED_KEY_WORDS][4];
    uint8_t current_key[4][NB];             // Cela nous permettra de formater la clé pour add_round_key
    int NR = (key_size) / 4 + 6;            // Nombre de round

    // 1. Expansion de la clé
    key_expansion(key, w, key_size);

    // 2. Initialisation de l'État avec le texte clair
    init_state(in, state);

    // --- ROUND 0 ---
    // On extrait la clé du Round 0 (les 4 premiers mots de w)
    for (int c = 0; c < NB; c++) {
        for (int r = 0; r < 4; r++) {
            current_key[r][c] = w[c][r];
        }
    }
    add_round_key(state, current_key);
    
    // --- ROUND 1 à NR-1 ---
    for (int round = 1; round < NR; round++) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        
        // Extraction de la clé pour le round en cours (mots : round*4 à round*4 + 3)
        for (int c = 0; c < NB; c++) {
            for (int r = 0; r < 4; r++) {
                current_key[r][c] = w[round * 4 + c][r];
            }
        }
        add_round_key(state, current_key);
    }

    // --- ROUND FINAL (NR) ---
    sub_bytes(state);
    shift_rows(state);

    // Extration de la clé du dernier round (mots : 40 à 43)
    for (int c = 0; c < NB; c++) {
        for (int r = 0; r < 4; r++) {
            current_key[r][c] = w[NR * 4 + c][r];
        }
    }
    add_round_key(state, current_key);

    // 3. Copie de l'État final dans un tableau de sortie 'out'
    for (int c = 0; c < NB; c++) {
        for (int r = 0; r < 4; r++) {
            out[r + 4 * c] = state[r][c];
        }
    }
}

/*
Fonction : inv_sub_bytes
------------------------
Opération inverse de SubBytes.
Utilise la S-box inverse pour restituer les octets lors du déchiffrement.
*/
void inv_sub_bytes(state_t state) {
    // On parcourt chaque colonne 
    for (int c = 0; c < NB; c++) {
        // On parcourt chaque ligne
        for (int r = 0; r < 4; r++) {
            // Remplacement de l'octet par sa valeur dans la S-box inverse
            state[r][c] = inv_sbox[state[r][c]];
        }
    }
}

/*
Fonction : inv_shift_rows
-------------------------
Opération inverse de ShiftRows.
Effectue un décalage circulaire des lignes de la matrice d'état vers la droite.
*/
void inv_shift_rows(state_t state) {
    uint8_t temp;

    // Ligne 1 : Décalage de 1 vers la droite
    temp = state[1][3];
    state[1][3] = state[1][2];
    state[1][2] = state[1][1];
    state[1][1] = state[1][0];
    state[1][0] = temp;

    // Ligne 2 : Décalage de 2 vers la droite
    temp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;
    temp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp;

    // Ligne 3 : Décalage de 3 vers la droite
    temp = state[3][0];
    state[3][0] = state[3][1];
    state[3][1] = state[3][2];
    state[3][2] = state[3][3];
    state[3][3] = temp;
}

/*
Fonction utilitaire : multiply
---------------------------
Multiplication générique de deux éléments dans GF(2^8).
Utilise l'algorithme de multiplication dite Shift-and-add 
adapté pour les corps finis. La fonction s'appuie sur la primitive xtime() 
pour multiplier par 2 à chaque itération.

Paramètres :
    - x, y : Les deux octets (polynômes) à multiplier.
Retourne :
    - Le produit x * y dans GF(2^8).
*/
static uint8_t multiply(uint8_t x, uint8_t y) {
    uint8_t result = 0;
    uint8_t temp = x;

    // On boucle tant que qu'il reste des 1 bits à y
    while (y != 0) {
        // Si le bit de poids faible est 1, on ajoute temp au résultat (XOR)
        if (y & 1) {
            result ^= temp;
        }

        // On multiple temp par 2 pour le prochain tour
        temp = xtime(temp);

        // On décale y vers la droite pour traiter le bit suivant
        y >>= 1;
    }

    return result;
}

/*
Fonction : inv_mix_columns
--------------------------
Opération inverse de MixColumns.
Multiplie chaque colonne par le polynôme inverse 
d(x) = {0b}x^3 + {0d}x^2 + {09}x + {0e} modulo x^4 + 1.
*/
void inv_mix_columns(state_t state) {
    uint8_t col[4];

    // On parcourt chaque colonne
    for (int c = 0; c < NB; c++) {
        // On sauvegarde la colonne d'origine car on va écraser les valeurs de 'state'
        for (int r = 0; r < 4; r++) {
            col[r] = state[r][c];
        }

        // On applique les multiplications croisées avec la matrice inverse
        state[0][c] = multiply(col[0], 0x0e) ^ multiply(col[1], 0x0b) ^ multiply(col[2], 0x0d) ^ multiply(col[3], 0x09);
        state[1][c] = multiply(col[0], 0x09) ^ multiply(col[1], 0x0e) ^ multiply(col[2], 0x0b) ^ multiply(col[3], 0x0d);
        state[2][c] = multiply(col[0], 0x0d) ^ multiply(col[1], 0x09) ^ multiply(col[2], 0x0e) ^ multiply(col[3], 0x0b);
        state[3][c] = multiply(col[0], 0x0b) ^ multiply(col[1], 0x0d) ^ multiply(col[2], 0x09) ^ multiply(col[3], 0x0e);
    }
}

/*
Fonction : aes_decipher
-----------------------
Moteur principal de déchiffrement AES.
Applique les opérations inverses dans l'ordre mathématique approprié pour 
retrouver le bloc de texte clair original à partir d'un bloc chiffré.

Paramètres :
    - in       : Bloc de texte chiffré (16 octets).
    - key      : Clé de chiffrement maître.
    - out      : Bloc de texte clair restitué (16 octets).
    - key_size : Taille de la clé maître.
*/
void aes_decipher(const uint8_t in[16], const uint8_t *key, uint8_t out[16], AES_KEY_SIZE key_size) {
    state_t state;
    uint8_t w[MAX_EXPANDED_KEY_WORDS][4];
    uint8_t current_key[4][NB];
    int NR = (key_size / 4) + 6;

    // 1. Expansion de la clé
    key_expansion(key, w, key_size);

    // 2. Initialisation de l'État avec le texte chiffré
    init_state(in, state);

    // --- ROUND FINAL (NR) ---
    // On extrait la clé du Round NR (les 4 derniers mots de w)
    for (int c = 0; c < NB; c++) {
        for (int r = 0; r < 4; r++) {
            current_key[r][c] = w[NR * 4 + c][r];
        }
    }
    add_round_key(state, current_key);
    
    // --- ROUND NR-1 à 1 ---
    for (int round = NR - 1; round >= 1; round--) {
        inv_shift_rows(state);
        inv_sub_bytes(state);
        
        // Extraction de la clé pour le round actuel
        for (int c = 0; c < NB; c++) {
            for (int r = 0; r < 4; r++) {
                current_key[r][c] = w[round * 4 + c][r];
            }
        }
        add_round_key(state, current_key);

        inv_mix_columns(state);
    }

    // --- ROUND 0 ---
    inv_shift_rows(state);
    inv_sub_bytes(state);
    

    // Extration de la première clé (mots : 0 à 3   )
    for (int c = 0; c < NB; c++) {
        for (int r = 0; r < 4; r++) {
            current_key[r][c] = w[c][r];
        }
    }
    add_round_key(state, current_key);

    // 3. Copie de l'État final dans un tableau de sortie 'out'
    for (int c = 0; c < NB; c++) {
        for (int r = 0; r < 4; r++) {
            out[r + 4 * c] = state[r][c];
        }
    }
}

/* 
Fonction : get_msb_s
--------------------
Extrait les 's' bits de poids forts (Most Significant Bits) d'un tableau.
Correspond à la fonction MSB_s définie dans le NIST SP 800-38D (Section 6.1).
Note : 's_bits' doit être un multiple de 8.

Paramètres : 
    - in        : Tableau source.
    - out       : Tableau de destination.
    - s_bits    : Nombre de bits à extraire. 
*/
static void get_msb_s(const uint8_t *in, uint8_t *out, size_t s_bits) {
    size_t s_bytes = s_bits / 8;
    memcpy(out, in, s_bytes);
}

/*
Fonction : increment_counter
----------------------------
Incrémente les 32 bits de droites (4 octets) d'un bloc de 16 octets.
Correspond à la fonction inc_32 spécifié dans le NIST 800-38D (Section 6.2).
Les 96 bits de gauche restent inchangés. Fonction essentielle pour générer 
la séquence de compteurs en mode CTR et GCM.

Remarque : Cette écriture de la fonction est plus efficace sans utiliser 
MSB et LSB.

Paramètres :
    - counter : Bloc de compteur de 16 octets.
*/
void increment_compteur(uint8_t counter[16]) {
    for (int i = 15; i >= 12; i--) {
        counter[i]++;
        if (counter[i] != 0x00) {
            break;  // Pas de retenue, on arrête l'incrémentation
        }
    }
}

/*  
Fonction utilitaire : get_bit_at
--------------------------------
Extrait le i-ème bit d'un bloc de 16 octets (de gauche à droite).
Correspond à la notation xi de la séquence de bits x0, x1, ..., x127 
dans le NIST SP 800-38D (Section 6.3, Étape 2).

Paramètres :
  - block : Le bloc de 16 octets.
  - i     : L'index du bit (de 0 à 127).
Retourne : 0 ou 1.*/
static uint8_t get_bit_at(const uint8_t block[16], int i) {
    int byte_index = i / 8;
    int bit_index = 7 - (i % 8);
    return (block[byte_index] >> bit_index) & 1;
}

/*
Fonction : right_shift_block
----------------------------
Effectue un décalage d'un bit vers la droite (>> 1) sur un bloc 
entier de 128 bits. Les bits de poids faible glissent vers le 
poids fort de l'octet suivant.
Correspond à l'opération (Vi >> 1) du NIST SP 800-38D (Section 6.3).

Paramètres :
  - block : Le bloc de 16 octets (modifié en place).
*/
static void right_shift_block(uint8_t block[16]) {
    uint8_t carry = 0;
    for (int j = 0; j < 16; j++) {
        // La retenue pour l'octet suivant est le bit de poids faible actuel
        uint8_t next_carry = (block[j] & 1) << 7; 
        block[j] = (block[j] >> 1) | carry;
        carry = next_carry;
    }
}

/* 
Fonction utilitaire : xor_blocks
-----------------------------------
Applique XOR entre deux blocks de 16 octets
*/
void xor_blocks(uint8_t *dest,const uint8_t *src) {
    for (int i = 0; i < 16; i++) {
        dest[i] ^= src[i];
    }
}

/*
Fonction : gcm_mult
-------------------
Multiplication de deux blocs dans le corps de Galois GF(2^128).
Utilisé par le mode GCM pour calculer l'authentification (GHASH).
Implémentation fidèle de "Algorithm 1" (NIST SP 800-38D, Section 6.3).

Paramètres : 
    - X : Premier bloc opérante (16 octets).
    - Y : Deuxième bloc opérante (16 octets).
    - Z : Bloc résultant de l'opération X • Y (16 octets).
*/
void gcm_mult(const uint8_t X[16],const uint8_t Y[16], uint8_t Z[16]) {
    uint8_t V[16];

    // Constante R = 11100001 || 0^120 (NIST SP 800-38D, Section 6.3)
    uint8_t R[16] = {0xE1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    // Étape 1 & 2 : Z0 = 0^128 et V0 = Y
    memset(Z, 0, 16);
    memcpy(V, Y, 16);

    // Étape 3 : Boucle pour i = 0 à 127
    for (int i = 0; i < 128; i++) {

        // On extrait xi désigne le bit courant de X
        uint8_t x_i = get_bit_at(X, i);

        // Calcul de Zi+1
        if (x_i == 1) {
            xor_blocks(Z, V); // Zi+1 = Zi XOR Vi
        } // Sinon, Zi+1 = Zi

        // Extraction de LSB_1(Vi) avant de décaler V
        uint8_t lsb_V = V[15] & 1;

        // Calcul de Vi+1
        right_shift_block(V); // Vi >> 1

        if (lsb_V == 1) {
            xor_blocks(V, R); // Vi+1 = (Vi >> 1) XOR R
        }
    }
    // Étape 4 : Retourne Z (qui contient Z_128)
}

/*
Fonction : ghash
----------------
Calcule l'empreinte d'authentification GHASH sur un ensemble de données.
Implémentation fidèle de "Algorithm 2" (NIST SP 800-38D, Section 6.4).
Cette fonction divise les données d'entrée en blocs de 16 octets et les
compresse successivement en utilisant la multiplication dans GF(2^128).

Paramètres :
    - H         : La sous-clé de hachage de 16 octets (Hash subkey).
    - X         : Pointeur vers les données d'entrée. Sa taille en octets doit
                obligatoirement être un multiple de 16.
    - len_bytes : La taille totale des données X en octets.
    - Y         : Le bloc de sortie résultant (16 octets).
*/
void ghash(const uint8_t H[16], const uint8_t *X, size_t len_bytes, uint8_t Y[16]) {
    
    // Étape 1 : X est découpé en block de 16 octets (X1, ..., Xm)
    size_t m = len_bytes / 16;
    uint8_t temp_mult[16];

    // Étape 2 : Y0 est le "zero block" (128 bits à 0)
    memset(Y, 0, 16);

    // Étape 3 : Boucle sur chaque bloc Xi
    for (size_t i = 0; i < m; i++) {
        // Opération : (Yi-1 XOR Xi)
        for (int j = 0; j < 16; j++) {
            Y[j] ^= X[i * 16 + j];
        }

        // Opération : • H
        // Remarque : on multiplie par la sous-clé H. On utilise temp_mult en sortie 
        // pour éviter d'écraser Y pendant l'initialisation dans gcm_mult.
        gcm_mult(Y, H, temp_mult);

        // Le résultat devient le nouveau Yi pour le prochain tour
        memcpy(Y, temp_mult, 16);
    }
    // Étape 4 : Y contient maintenant Ym
}

/*
Fonction : gctr
---------------
Implémente la fonction GCTR (Galois Counter) définie dans le NIST SP 800-38D
(Algo 3, Section 6.5).
Chiffre et déchiffre les données en utilisant le mode Counter. La grande force
du GCTR est qu'il n'utilise aucun padding : le dernier bloc est tronqué.

Paramètres : 
    - ICB       : Initial Counter Block (16 octets). Bloc de compteur de départ.
    - X         : Données d'entrée (texte clair / chiffré).
    - len_bytes : Taille totale des données X en octets.
    - key       : Clé de chiffrement maître.
    - key_size  : Taille de la clé maître.
    - Y         : Tampon de sortie (même taille que X à allouer).
*/
void gctr(uint8_t ICB[16], const uint8_t *X, size_t len_bytes, const uint8_t *key, AES_KEY_SIZE key_size, uint8_t *Y) {
    
    // Étape 1 : Si rien à dé/chiffrer
    if (len_bytes == 0) { 
        return; // 
    }

    uint8_t CB[16];
    uint8_t CIPH[16];

    // Étape 2 : Calcul du nombre total de blocs 'n'
    size_t n = (len_bytes + 15) / 16;
    
    // Étape 4 : CB1 = ICB
    memcpy(CB, ICB, 16);

    // Étape 5 & 6 : Boucles sur les blocs
    for (size_t i = 0; i < n; i++) {
        aes_cipher(CB, key, CIPH, key_size);

        // Détermination de la taille du bloc courant
        size_t block_len = 16;
        if (i == n - 1 && (len_bytes % 16) != 0) {
            block_len = len_bytes % 16;
        }

        for (size_t j = 0; j < block_len; j++) {
            Y[i * 16 + j] = X[i * 16 + j] ^ CIPH[j];
        }

        if (i < n - 1) {
            increment_compteur(CB);
        }
    }
}

/*
Fonction utilitaire : put_uint64_be
-----------------------------------
Insère un entier de 64 bits en format Big-Endiandans un tableau d'octets.
Indispensable pour formater les longueurs dans le bloc final du GHASH.
*/
static void put_uint64_be(uint64_t val, uint8_t *out) {
    for (int i = 7; i >= 0; i--) {
        out[i] = (uint8_t)(val & 0xFF);
        val >>= 8;
    }
}

/*
Fonction : gcm_encrypt_ae
-------------------------
Chiffrement Authentifié GCM (GCM-AE).
Implémente "Algorithm 4" (NIST SP 800-38D, Section 7.1).

Paramètres :
    - key, key_size : La clé maître AES et sa taille.
    - iv            : Le Vecteur d'Initialisation (Recommandé et forcé ici à 12 octets / 96 bits).
    - aad, aad_len  : Additional Authenticated Data (peut être NULL / 0).
    - pt, pt_len    : Plaintext (texte clair à chiffrer).
    - ct            : Tampon de sortie pour le Ciphertext (même taille que pt).
    - tag           : Tampon de sortie pour le Tag d'authentification.
    - tag_len       : Taille désirée du Tag en octets (ex: 16 pour 128 bits).
*/
void gcm_encrypt_ae(const uint8_t *key, AES_KEY_SIZE key_size, const uint8_t iv[12], const uint8_t *aad, size_t aad_len, const uint8_t *pt, size_t pt_len, uint8_t *ct, uint8_t *tag, size_t tag_len) {
    uint8_t H[16];
    uint8_t zeros[16] = {0};

    // 1. Génération de H = CIPH_K(0^128)
    aes_cipher(zeros, key, H, key_size);

    // 2. Définition de J0 (avec le standard 96 bits pour IV)
    uint8_t J0[16] = {0};
    memcpy(J0, iv, 12);
    J0[15] = 0x01; // On ajoute 0^31 || 1 à la fin
    
    // 3. Calcul du Ciphertext (C) avec GCTR
    uint8_t J0_inc[16];
    memcpy(J0_inc, J0, 16);
    increment_compteur(J0_inc); // Le compteur démarre à J0 + 1
    gctr(J0_inc, pt, pt_len, key, key_size, ct);

    // 4. Préparation du bloc de donnée pour GHASH
    //      (A∣∣0^v∣∣C∣∣0^u∣∣[len(A)]_64​∣∣[len(C)]_64​)
    // Calcul du padding u et v pour s'aligner sur des blocs de 16 octets
    size_t u = (16 - (pt_len % 16)) % 16;
    size_t v = (16 - (aad_len % 16)) % 16;
    size_t ghash_in_len = pt_len + u + aad_len + v + 16; // +16 pour le bloc des longueurs

    // calloc initialise tout à 0, ce qui gère le padding de u et v
    uint8_t *ghash_in = calloc(ghash_in_len, 1);

    size_t offset = 0;

    // 4a. Ajout de AAD
    if (aad_len > 0) {
        memcpy(ghash_in + offset, aad, aad_len);
    }
    offset += aad_len + v; // On saute le padding (qui est déjà à 0)
    
    // 4b. Ajout du Ciphertext
    if (pt_len > 0) {
        memcpy(ghash_in + offset, ct, pt_len);
    }
    offset += pt_len + u; // On saute le padding
    
    // 4c. Ajout des longueurs en BITS (sur 64 bits chacune)
    uint64_t aad_bit_len = (uint64_t)aad_len * 8;
    uint64_t pt_bit_len  = (uint64_t)pt_len * 8;
    put_uint64_be(aad_bit_len, ghash_in + offset);
    put_uint64_be(pt_bit_len, ghash_in + offset + 8);
    
    // 5. Calcul de S = GHASH_H(A || pad(A) || C || pad(C) || len(A) || len(C))
    uint8_t S[16];
    ghash(H, ghash_in, ghash_in_len, S);
    free(ghash_in); // On libère la mémoire
    
    // 6. Calcul du Tag final (T) = MSB_t(GCTR_K(J0, S))
    uint8_t full_tag[16];
    gctr(J0, S, 16, key, key_size, full_tag);
    
    get_msb_s(full_tag, tag, tag_len * 8);
}

/*
Fonction : gcm_decrypt_ad
-------------------------
Déchiffrement Authentifié GCM (GCM-AD).
Implémente "Algorithme 5" (NIST 800-38D, Section 7.2).

Paramètres :
  - key, key_size : La clé maître AES et sa taille.
  - iv            : Le Vecteur d'Initialisation (12 octets / 96 bits).
  - aad, aad_len  : Additional Authenticated Data (peut être NULL / 0).
  - ct, ct_len    : Ciphertext (texte chiffré à vérifier et déchiffrer).
  - expected_tag  : Le Tag d'authentification lu dans le fichier/message.
  - tag_len       : Taille du Tag en octets (ex: 16).
  - pt            : Tampon de sortie pour le Plaintext (même taille que ct).

Retourne :
  - true (1) si le Tag est valide (Authenticité garantie).
  - false (0) si le Tag est invalide (Fichier corrompu ou piraté !).
*/
bool gcm_decrypt_ad(const uint8_t *key, AES_KEY_SIZE key_size, const uint8_t iv[12], const uint8_t *aad, size_t aad_len, const uint8_t *ct, size_t ct_len, const uint8_t *expected_tag, size_t tag_len, uint8_t *pt) {
    
    uint8_t H[16];
    uint8_t zeros[16] = {0};

    // 1. Génération de H = CIPH_K(0^128)
    aes_cipher(zeros, key, H, key_size);

    // 2. Définition de J0
    uint8_t J0[16] = {0};
    memcpy(J0, iv, 12);
    J0[15] = 0x01;

    // 3. Préparation du bloc de données pour GHASH
    size_t u = (16 - (ct_len % 16)) % 16;
    size_t v = (16 - (aad_len % 16)) % 16;
    size_t ghash_in_len = ct_len + u + aad_len + v + 16;

    // calloc initialise tout à 0, ce qui gère le padding de u et v
    uint8_t *ghash_in = calloc(ghash_in_len, 1);

    size_t offset = 0;

    // 4a. Ajout de AAD
    if (aad_len > 0) {
        memcpy(ghash_in + offset, aad, aad_len);
    }
    offset += aad_len + v; // On saute le padding (qui est déjà à 0)
    
    // 4b. Ajout du Ciphertext
    if (ct_len > 0) {
        memcpy(ghash_in + offset, ct, ct_len);
    }
    offset += ct_len + u; // On saute le padding
    
    // 4c. Ajout des longueurs en BITS (sur 64 bits chacune)
    uint64_t aad_bit_len = (uint64_t)aad_len * 8;
    uint64_t pt_bit_len  = (uint64_t)ct_len * 8;
    put_uint64_be(aad_bit_len, ghash_in + offset);
    put_uint64_be(pt_bit_len, ghash_in + offset + 8);
    
    // 6. Calcul de S = GHASH_H(A || pad(A) || C || pad(C) || len(A) || len(C))
    uint8_t S[16];
    ghash(H, ghash_in, ghash_in_len, S);
    free(ghash_in); // On libère la mémoire
    
    // 7. Calcul du Tag (T')
    uint8_t full_tag[16];
    gctr(J0, S, 16, key, key_size, full_tag);

    uint8_t calculated_tag[16];
    get_msb_s(full_tag, calculated_tag, tag_len * 8);

    // 8. Vérification Cryptographique
    uint8_t diff = 0;
    for (size_t i = 0; i < tag_len; i++) {
        diff |= (calculated_tag[i] ^ expected_tag[i]);
    }
    
    if (diff != 0) {
        // ALERTE : Le tag ne correspond pas ! FAIL.
        return false;
    }

    // Si (et seulement si) le tag est valide, on déchiffre !
    uint8_t J0_inc[16];
    memcpy(J0_inc, J0, 16);
    increment_compteur(J0_inc);
    
    gctr(J0_inc, ct, ct_len, key, key_size, pt);
    
    return true; // Succès !

}






