#ifndef AES_H
#define AES_H

#include <stdint.h>

// Définitions des paramètres pour l'AES-128
#define NB 4
#define NK 4
#define NR 10

// Définition de notre type pour l'État (State)
// Un tableau 2D de 4 lignes et 4 colonnes d'octets
typedef uint8_t state_t[4][NB];

// Prototype de notre fonction d'initialisation
void init_state(const uint8_t in[16], state_t state);

// Prototype pour pouvoir afficher notre État 
void print_state(const state_t state);

// Prototype de la fonction de substitution des octets (S-box)
void sub_bytes(state_t state);

// Prototype de la fonction de décalage des lignes
void shift_rows(state_t state);

// Prototype de l'ajout de la clé
void add_round_key(state_t state, const uint8_t round_key[4][NB]);

// Prototype du mélange des colonnes
void mix_columns(state_t state);

// Prototype de l'expansion de la clé
void key_expansion(const uint8_t key[16], uint8_t w[44][4]);

// Fonction principale de chiffrement (AES-128)
void aes_cipher(const uint8_t in[16], const uint8_t key[16], uint8_t out[16]);

// Prototype de la fonction inverse de substitution des octets (avec S-box inverse)
void inv_sub_bytes(state_t state);

// Prototype de la fonction inverse de décalage des lignes
void inv_shift_rows(state_t state);

// Prototype inverse du mélange des colonnes
void inv_mix_columns(state_t state);

// Fonction principale de déchiffrement (AES-128)
void aes_decipher(const uint8_t in[16], const uint8_t key[16], uint8_t out[16]);


#endif /* AES_H */