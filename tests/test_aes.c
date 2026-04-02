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
    RESULTAT ATTENDU (Début du Round 1 sur ton image) :
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
    RESULTAT ATTENDU (Ligne 'Round 1', 4ème case de ton image) :
    04 e0 48 28 
    66 cb f8 06 
    81 19 d3 26 
    e5 9a 7a 4c 
     */

    return 0;
}