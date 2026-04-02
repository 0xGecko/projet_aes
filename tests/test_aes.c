#include <stdio.h>
#include "../include/aes.h"

int main() {
    // 1. Le bloc d'entrée exact donné dans l'exemple du standard FIPS-197 (Annexe B)
    uint8_t input[16] = {
        0x32, 0x43, 0xf6, 0xa8,
        0x88, 0x5a, 0x30, 0x8d,
        0x31, 0x31, 0x98, 0xa2,
        0xe0, 0x37, 0x07, 0x34
    };

    // 2. Déclaration de notre matrice d'état
    stat_t state;

    printf("--- Test d'initialisation de l'État (AES-128) ---\n\n");

    // 3. Appel de notre fonction
    init_state(input, state);

    // 4. Affichage du résultat
    printf("Etat initial apres init_state\n");
    print_state(state);

    return 0;
}