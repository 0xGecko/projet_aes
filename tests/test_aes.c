#include <stdio.h>
#include "../include/aes.h"

int main() {
    // Le bloc d'entrée exact donné dans l'exemple du standard FIPS-197 (Annexe B)
    uint8_t input[16] = {
        0x32, 0x43, 0xf6, 0xa8,
        0x88, 0x5a, 0x30, 0x8d,
        0x31, 0x31, 0x98, 0xa2,
        0xe0, 0x37, 0x07, 0x34
    };

    // Déclaration de notre matrice d'état
    state_t state;

    printf("\n--- Test d'initialisation de l'État (AES-128) ---\n\n");
    init_state(input, state);
    printf("Etat initial apres init_state\n");
    print_state(state);

    printf("--- Test de SubBytes ---\n\n");
    sub_bytes(state);
    printf("Etat après sub_bytes\n");
    print_state(state);

    /* 
    RESULTAT ATTENDU (selon l'Annexe B du FIPS 197) :
    23 c4 c7 e1 
    1a be c7 9a 
    42 04 46 c5 
    c2 5d 3a 18 
    */

    printf("--- Test de ShiftRows ---\n\n");
    shift_rows(state);
    printf("Etat après shift_rows\n");
    print_state(state);
    
    /*
    RESULTAT ATTENDU (selon l'Annexe B du FIPS 197) :
    23 c4 c7 e1
    be c7 9a 1a
    46 c5 42 04
    18 c2 5d 3a
    */
    
    printf("--- Test de AddRoundKey (Round 0) ---\n\n");
    
    // On réinitialise l'état avec notre input d'origine pour repartir à zéro
    init_state(input, state);
    
    // La clé initiale donnée dans l'Annexe B (la matrice tout à droite de la ligne Input)
    uint8_t key[4][NB] = {
        {0x2b, 0x28, 0xab, 0x09},
        {0x7e, 0xae, 0xf7, 0xcf},
        {0x15, 0xd2, 0x15, 0x4f},
        {0x16, 0xa6, 0x88, 0x3c}
    };
    
    // On applique la fonction
    add_round_key(state, key);
    
    // On affiche le résultat
    printf("Etat apres AddRoundKey initial :\n");
    print_state(state);

    /*
    RESULTAT ATTENDU (Début du Round 1 du FIPS 197) :
    19 a0 9a e9 
    3d f4 c6 f8 
    e3 e2 8d 48 
    be 2b 2a 08 
    */

    printf("--- Test complet d'un demi-Round (Round 1) ---\n\n");
    
    // L'état actuel est celui de la 1ère colonne du "Round 1"
    // On applique la séquence classique d'un round
    sub_bytes(state);
    shift_rows(state);
    mix_columns(state);
    
    printf("Etat apres SubBytes, ShiftRows et MixColumns :\n");
    print_state(state);

    /*
    RESULTAT ATTENDU (Ligne 'Round 1', 4ème case du FIPS 197) :
    04 e0 48 28 
    66 cb f8 06 
    81 19 d3 26 
    e5 9a 7a 4c 
    */
    
    printf("--- Test de KeyExpansion ---\n\n");

    // Clé d'exemple de l'annexe A.1
    uint8_t cipher_key[16] = {
        0x2b, 0x7e, 0x15, 0x16,
        0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88,
        0x09, 0xcf, 0x4f, 0x3c
    };

    // Notre tableau pour stocker les 44 mots
    uint8_t w[44][4];

    // On lance l'expansion
    key_expansion(cipher_key, w);

    // On check la toute dernière clé (Round 10), qui correspond aux 4 derniers mots (w[40] à w[43])
    printf("Cle du Round 10 :\n");
    for (int i = 40; i < 44; i++) {
        printf("%02x %02x %02x %02x\n", w[i][0], w[i][1], w[i][2], w[i][3]);
    }

    /*
    RESULTAT ATTENDU (Annexe A.1, fin du tableau) :
    d0 14 f9 a8
    c9 ee 25 89
    e1 3f 0c c8
    b6 63 0c a6
    */

    printf("\n\n--- Test final : Chiffrement Complet (AES-128) ---\n");

    uint8_t out[16];

    aes_cipher(input, cipher_key, out);

    printf("Ciphertext :\n");
    for (int c = 0; c < 4; c++) {
        for (int r = 0; r < 4; r++) {
            printf("%02x ", out[c + 4 * r]);
        }
        printf("\n");
    }
    printf("\n\n");

    /*
    RESULTAT ATTENDU (Annexe B, fin du tableau) :
    39 02 dc 19
    25 dc 11 6a
    84 09 85 0b
    1d fb 97 32
    */

    printf("--- Test de InvSubBytes ---\n\n");

    // On réinitialise l'état avec notre texte clair de départ
    init_state(input, state);
    printf("1. Etat de depart :\n");
    for (int r = 0; r < 4; r++) {
        for (int c = 0; c < 4; c++) printf("%02x ", state[r][c]);
        printf("\n");
    }
    printf("\n");

    // On applique SubBytes et InvSubBytes
    sub_bytes(state);
    inv_sub_bytes(state);

    printf("3. Etat apres InvSubBytes :\n");
    for (int r = 0; r < 4; r++) {
        for (int c = 0; c < 4; c++) printf("%02x ", state[r][c]);
        printf("\n");
    }
    printf("\n");

    /*
    RESULTAT ATTENDU :
    32 88 31 e0 
    43 5a 31 37 
    f6 30 98 07 
    a8 8d a2 34 
    */

    printf("--- Test de InvShiftRows ---\n\n");

    init_state(input, state);
    shift_rows(state);
    inv_shift_rows(state);

    printf("Etat après ShiftRows puis InvShiftRows :\n");
    for (int r = 0; r < 4; r++) {
        for (int c = 0; c < NB; c++) {
            printf("%02x ", state[r][c]);
        }
        printf("\n");
    }
    printf("\n");

    printf("--- Test de InvMixColumns ---\n\n");

    init_state(input, state);
    mix_columns(state);
    inv_mix_columns(state);

    printf("Etat après MixColumns puis InvMixColumns :\n");
    for (int r = 0; r < 4; r++) {
        for (int c = 0; c < NB; c++) {
            printf("%02x ", state[r][c]);
        }
        printf("\n");
    }
    printf("\n");

    printf("\n\n--- Test final : Déhiffrement Complet (AES-128) ---\n");

    uint8_t decrypted[16];

    aes_decipher(out, cipher_key, decrypted);

    printf("Text déchiffré :\n");
    for (int c = 0; c < 4; c++) {
        for (int r = 0; r < 4; r++) {
            printf("%02x ", decrypted[c + 4 * r]);
        }
        printf("\n");
    }
    printf("\n\n");

    /*
    RESULTAT ATTENDU (Annexe B, fin du tableau) :
    32 88 31 e0 
    43 5a 31 37 
    f6 30 98 07 
    a8 8d a2 34 
    */

    
    return 0;
}