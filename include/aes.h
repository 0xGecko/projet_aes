#ifndef AES_H
#define AES_H

#include <stdint.h>
#include <stdbool.h>

// Le nombre de colonnes de l'État (State) est toujours de 4 pour l'AES
#define NB 4

// Définitions des tailles de clés possibles en octets
typedef enum {
    AES_128 = 16, // 16 octets = 128 bits (Nk=4, Nr=10)
    AES_192 = 24, // 24 octets = 192 bits (Nk=6, Nr=12)
    AES_256 = 32, // 32 octets = 256 bits (Nk=8, Nr=14)
} AES_KEY_SIZE;

// Le tableau des clés étendues (RoundKey) doit pouvoir contenir la plus grande taille possible.
// Remarque pour AES-256 : (14 tours + 1) * 4 mots de 32 bits = 60 mots.
#define MAX_EXPANDED_KEY_WORDS 60

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

// NOUVEAU PROTOTYPE : On passe la taille de la clé et on augmente la taille de 'w'
void key_expansion(const uint8_t *key, uint8_t w[MAX_EXPANDED_KEY_WORDS][4], AES_KEY_SIZE key_size);

// NOUVEAU PROTOTYPE : 'key' devient un pointeur pour accepter 16, 24 ou 32 octets
void aes_cipher(const uint8_t in[16], const uint8_t *key, uint8_t out[16], AES_KEY_SIZE key_size);

// Prototype de la fonction inverse de substitution des octets (avec S-box inverse)
void inv_sub_bytes(state_t state);

// Prototype de la fonction inverse de décalage des lignes
void inv_shift_rows(state_t state);

// Prototype inverse du mélange des colonnes
void inv_mix_columns(state_t state);

// NOUVEAU PROTOTYPE : 'key' devient un pointeur
void aes_decipher(const uint8_t in[16], const uint8_t *key, uint8_t out[16], AES_KEY_SIZE key_size);

// Prototype : Incrémente 32 bits les plus à droite dans un bloc de 16 octets
void increment_compteur(uint8_t counter[16]);

//  Prototype : Applique XOR entre deux blocks de 16 octets
void xor_blocks(uint8_t *dest, const uint8_t *src);

// Prototype : Multiplie 2 blocs de 16 octets dans GF(2^128)
void gcm_mult(const uint8_t X[16],const uint8_t Y[16], uint8_t Z[16]);

// Prototype : Calcule l'empreinte d'authentification GHASH sur un ensemble de données.
void ghash(const uint8_t H[16], const uint8_t *X, size_t len_bytes, uint8_t Y[16]);

// Prototype : Implémente la fonction GCTR (Galois Counter)
void gctr(uint8_t ICB[16], const uint8_t *X, size_t len_bytes, const uint8_t *key, AES_KEY_SIZE key_size, uint8_t *Y);

// Prototype : Chiffrement Authentifié GCM (GCM-AE)
void gcm_encrypt_ae(const uint8_t *key, AES_KEY_SIZE key_size, const uint8_t iv[12], const uint8_t *aad, size_t aad_len, const uint8_t *pt, size_t pt_len, uint8_t *ct, uint8_t *tag, size_t tag_len);

// Prototype : Déchiffrement Authentifié GCM (GCM-AD)
bool gcm_decrypt_ad(const uint8_t *key, AES_KEY_SIZE key_size, const uint8_t iv[12], const uint8_t *aad, size_t aad_len, const uint8_t *ct, size_t ct_len, const uint8_t *expected_tag, size_t tag_len, uint8_t *pt);
#endif /* AES_H */