#ifndef AES_H
#define AES_H

#include <stdint.h>

// Définitions des paramètres pour l'AES-128
#define NB 4
#define NK 4
#define NR 10

// Définition de notre type pour l'État (State)
// Un tableau 2D de 4 lignes et 4 colonnes d'octets
typedef uint8_t stat_t[4][NB];

// Prototype de notre fonction d'initialisation
void init_state(const uint8_t in[16], stat_t state);

// Prototype pour pouvoir afficher notre État 
void print_state(const stat_t state);
    
#endif /* AES_H */