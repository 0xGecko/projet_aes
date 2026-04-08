#include <stdio.h>
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

/* Tableau des constantes de tour (Rcon) pour l'AES-128
On place 0x00 à l'indice 0 pour que rcon[1] corresponde bien au Round 1.
-----------
Remarque : 
Rcon est censé être un mot de 4 octets de type [x, 0, 0, 0], mais vu que seuls
les premiers octets changent, on ne stocke que ce premier octet en C (petite économie de place)
*/
static const uint8_t rcon[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

/*
Fonction : init_state
---------------------
Copie un bloc de 16 octets (128 bits dans la matrice carré d'État (State).
La copie se fait colonne par colonne, conformément au standard FIPS-197.

    in    : Le tableau d'entrée d'une dimension (16 octets).
    state : La matrice d'état de 4 lignes et colonnes qui sera modifiée.
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
Affiche la matrice d'état sous forme de grille 4x4 en hexadécimal.
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
Applique la subtitution non-linéaire (S-box) à chaque octet de l'État.
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
Effectue un décalage cyclique vers la gauche des lignes de l'État.
Ligne 0 : pas de décalage
Ligne 1 : décalage de 1
Ligne 2 : décalage de 2
Ligne 3 : décalage de 3
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
Multiplie un octet par 2 dans le corps de Galois GF(2^8).
*/
static uint8_t xtime(uint8_t x) {
    // Si le bit de poids fort est 1, on décale et on XOR avec 01xb
    // Sinon, on fait juste un décalage
    return (x & 0x80) ? (x << 1) ^ 0x1b : (x << 1);
}

/*
Fonction  : mix_columns
Mélange les données de chaque colonne de l'État de manière indépendante.
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
Applique la clé à chaque octet de l'État.
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
Fonction : key_expansion
------------------------
Étend la clé initiale de 16 octets en 44 mots (words) de 4 octets (pour 11 clés de rounds).
*/
void key_expansion(const uint8_t key[16], uint8_t w[44][4]) {
        uint8_t temp[4];

        // 1. Les 4 premiers mots (i < Nk = 4) sont simplement la clé d'origine
        for (int i = 0; i < 4; i++) {
            w[i][0] = key[4 * i];
            w[i][1] = key[4 * i + 1];
            w[i][2] = key[4 * i + 2];
            w[i][3] = key[4 * i + 3];
        }

        // 2. Calcul des 40 mots suivants (i de 4 à 43)
        for (int i = 4; i < 44; i++) {
            // On copie le mot précédent dans temp
            temp[0] = w[i - 1][0];
            temp[1] = w[i - 1][1];
            temp[2] = w[i - 1][2];
            temp[3] = w[i - 1][3];
            
            // Tous les 4 mots (i.e. début d'un nouveau round), on applique la transformation spéciale 
            // dans le pseudo-code de la Fig 11.
            if (i % 4 == 0) {
                // a) Rotword : décalage cycle d'un octet vers la gauche
                uint8_t t = temp[0];
                temp[0] = temp[1];
                temp[1] = temp[2];
                temp[2] = temp[3];
                temp[3] = t;

                // b) Subword : on passe chaque octet dans la S-box
                temp[0] = sbox[temp[0]];
                temp[1] = sbox[temp[1]];
                temp[2] = sbox[temp[2]];
                temp[3] = sbox[temp[3]];

                // c) XOR avec la constante de Round (Rcon) sur le premier octet
                temp[0] ^= rcon[i / 4];
            }

            // 3. On génère le nouveau mot en faisant un XOR avec le mot de 4 crans en arrière
            w[i][0] = w[i - 4][0] ^ temp[0];
            w[i][1] = w[i - 4][1] ^ temp[1];
            w[i][2] = w[i - 4][2] ^ temp[2];
            w[i][3] = w[i - 4][3] ^ temp[3];
        }
}

/*
Fonction : aes_cipher
---------------------
Chiffre un bloc de 16 octets avec une clé de 16 octets.
*/
void aes_cipher(const uint8_t in[16], const uint8_t key[16], uint8_t out[16]) {
    state_t state;
    uint8_t w[44][4];
    uint8_t current_key[4][NB]; // Cela nous permettra de formater la clé pour add_round_key

    // 1. Expansion de la clé
    key_expansion(key, w);

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
    
    // --- ROUND 1 à 9 ---
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

    // --- ROUND 10 ---
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
Applique la subtitution non-linéaire inverse (S-box inverse) à chaque octet de l'État.
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
Effectue un décalage cyclique vers la droite des lignes de l'État.
Ligne 0 : pas de décalage
Ligne 1 : décalage de 1
Ligne 2 : décalage de 2
Ligne 3 : décalage de 3
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
Multiplie 2 octets (x et y) dans le corps de Galois GF(2^8).
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
Mélange les données de chaque colonne de l'État en utilisant la matrice inverse.
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
Déchiffre un bloc de 16 octets (texte chiffré) avec une clé de 16 octets
*/
void aes_decipher(const uint8_t in[16], const uint8_t key[16], uint8_t out[16]) {
    state_t state;
    uint8_t w[44][4];
    uint8_t current_key[4][NB]; // Cela nous permettra de formater la clé pour add_round_key

    // 1. Expansion de la clé
    key_expansion(key, w);

    // 2. Initialisation de l'État avec le texte chiffré
    init_state(in, state);

    // --- ROUND 10 ---
    // On extrait la clé du Round 10 (les 4 derniers mots de w)
    for (int c = 0; c < NB; c++) {
        for (int r = 0; r < 4; r++) {
            current_key[r][c] = w[NR * 4 + c][r];
        }
    }
    add_round_key(state, current_key);
    
    // --- ROUND 9 à 1 ---
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
