#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <getopt.h>
#include "../include/aes.h"

// Définitions des modes d'opérations supportés
typedef enum {
    MODE_ECB,
    MODE_CBC,
    MODE_CFB,
    MODE_OFB,
    MODE_GCM
} BLOCK_CIPHER_MODE;

// Fonction permettant l'affichage de l'aide
static void print_usage(FILE *out) {
    fprintf(out, 
        "Utilisation : ./aes [OPTIONS] fichier_entree fichier_sortie\n"
        "Chiffre ou déchiffre un fichier en utilisant l'AES.\n\n"
        "Options :\n"
        "   -e, --encrypt   Chiffrer le fichier (Default)\n"
        "   -d, --decrypt   Déchiffrer le fichier\n"
        "   -h, --help      Affichage de l'aide\n"
        "   -s, --size,     Taille de la clé en bits : 128 (défaut), 192 ou 256\n"
        "   -k, --key,      Spécifier une clé en héxadécimal (32 caractères).\n"
        "   -m, --mode,     Mode d'opéraions : ecb (défaut), cbc, cfb, ofb ou gcm\n"
        "   -v, --iv,      Vecteur d'initialisation (IV) en hexadécimal (32 caractères) pour CBC\n"
    );
}

// Fonction sécurisée pour la conversion de la clé
void hex_to_bytes(const char* hex, uint8_t* bytes, int byte_len) {
    for (int i = 0; i < byte_len; i++) {
        unsigned int temp_val;
        sscanf(hex + 2 * i, "%2x", &temp_val);
        bytes[i] = (uint8_t)temp_val;
    }
}

// Fonction pour traiter le fichier (Chiffrement ECB ou CBC avec Padding PKCS#7)
static void process_file(FILE *in_file, FILE *out_file, bool encrypting, const uint8_t *key, AES_KEY_SIZE key_size, BLOCK_CIPHER_MODE mode, uint8_t *iv) {
    uint8_t buffer[16];
    uint8_t output[16];
    size_t bytes_read;
    size_t last_bytes_read = 0; 

    // ==========================================
    //           TRAITEMENT SPÉCIAL GCM
    // ==========================================
    if (mode == MODE_GCM) {
        // On calcule  la taille totale du fichier
        fseek(in_file, 0, SEEK_END);
        long file_size = ftell(in_file);
        fseek(in_file, 0, SEEK_SET);

        if (encrypting) {
            // --- CHIFFREMENT GCM ---
            uint8_t *pt = malloc(file_size);
            uint8_t *ct = malloc(file_size);
            uint8_t tag[16];

            // On check la lecture sinon on aura des warnings de la part du compilateur
            if (file_size > 0) {
                if (fread(pt, 1, file_size, in_file) != (size_t)file_size) {
                    fprintf(stderr, "Avertissement : Erreur de lecture du fichier source.\n");
                }
            }

            // Dans NIST SP 800-38D, il est recommandé 12 octets pour l'IV en GCM.
            // On prend les 12 premiers octets de notre current_iv
            gcm_encrypt_ae(key,  key_size, iv, NULL, 0, pt, file_size, ct, tag, 16);

            // On écrit le texte chiffré, puis on colle notre tag de 16 octets à la fin
            if (file_size > 0) {
                fwrite(ct, 1, file_size, out_file);
            }
            fwrite(tag, 1, 16, out_file);

            free(pt);
            free(ct);
        } else {
            // --- DECHIFFREMENT GCM ---
            if (file_size < 16) {
                fprintf(stderr, "Erreur : Le fichier est trop petit pour contenir un Tag GCM.\n");
                return;
            }

            // La taille du texte chiffré est la taille du fichier moins les 16 octets du tag
            long ct_len = file_size - 16;
            uint8_t *ct = malloc(ct_len);
            uint8_t *pt = malloc(ct_len);
            uint8_t expected_tag[16];

            // On check la lecture sinon on aura des warnings de la part du compilateur
            if (ct_len > 0) {
                if (fread(ct, 1, ct_len, in_file) != (size_t)ct_len) {
                    fprintf(stderr, "Avertissement : Erreur de lecture du texte chiffré.\n");
                }
            }
            if (fread(expected_tag, 1, 16, in_file) != 16) {
                fprintf(stderr, "Avertissement : Erreur de lecture du Tag.\n");
            }
            
            bool is_valid = gcm_decrypt_ad(key, key_size, iv, NULL, 0, ct, ct_len, expected_tag, 16, pt);

            if (is_valid) {
                printf("\n[SUCCESS!!] Tag d'athentification valide. Fichier intègre !\n");
                fwrite(pt, 1, ct_len, out_file);
            } else {
                fprintf(stderr, "\n[CRITICAL ERROR!!] Tag d'authenfication INVALIDE !\n");
                fprintf(stderr, "Le fichier a été modifié, corrompu ou piraté. Déchiffrement annulé.\n");
                // Remarque : On n'écrit pas le fichier de sortie pour des raisons de sécurité
            }
            free(ct);
            free(pt);
        }
        return;
    }

    if (encrypting) {
        // ==========================================
        //               CHIFFREMENT
        // ==========================================
        if (mode == MODE_ECB) {
            // --- CHIFFREMENT ECB ---
            while ((bytes_read = fread(buffer, 1, 16, in_file)) > 0) {
                last_bytes_read = bytes_read; // On mémorise la taille lue
                if (bytes_read == 16) {
                    // Bloc incomplet : On va appliquer du Padding PKCS#7
                    uint8_t padding_value = 16 - bytes_read;
                    for (size_t i = bytes_read; i < 16; i++) {
                        buffer[i] = padding_value;
                    }
                }
                aes_cipher(buffer, key, output, key_size);
                fwrite(output, 1, 16, out_file);
            }

            // Remarque importante : Si le fichier tombe pile sur un multiple de 16,
            // il faut rajouter un bloc entier de padding (16 octets de valeur 16)
            if (feof(in_file) && last_bytes_read == 16) {
                for (int i = 0; i < 16; i ++) {
                    buffer[i] = 16;
                }
                aes_cipher(buffer, key, output, key_size);
                fwrite(output, 1, 16, out_file);
            }

        } else if (mode == MODE_CBC) {
            // --- CHIFFREMENT CBC ---
            while ((bytes_read = fread(buffer, 1, 16, in_file)) > 0) {
                last_bytes_read = bytes_read; // On mémorise la taille lue
                if (bytes_read < 16) {
                    // Bloc incomplet : On va appliquer du Padding PKCS#7
                    uint8_t padding_value = 16 - bytes_read;
                    for (size_t i = bytes_read; i < 16; i++) {
                        buffer[i] = padding_value;
                    }
                }

                // XOR du texte clair avec IV
                xor_blocks(buffer, iv);
                // On chiffre
                aes_cipher(buffer, key, output, key_size);
                // Le block chiffré devient l'IV pour le tour suivant
                memcpy(iv, output, 16);

                fwrite(output, 1, 16, out_file);
            }

            // Padding d'un bloc entier si multiple de 16
            if (feof(in_file) && last_bytes_read == 16) {
                for (int i = 0; i < 16; i ++) {
                    buffer[i] = 16;
                }
                xor_blocks(buffer, iv);
                aes_cipher(buffer, key, output, key_size);
                memcpy(iv, output, 16);

                fwrite(output, 1, 16, out_file);
            }
        } else if (mode == MODE_CFB) {
            // --- CHIFFREMENT CFB ---
            while ((bytes_read = fread(buffer, 1, 16, in_file)) > 0) {
                last_bytes_read = bytes_read; // On mémorise la taille lue
                if (bytes_read < 16) {
                    // Bloc incomplet : On va appliquer du Padding PKCS#7
                    uint8_t padding_value = 16 - bytes_read;
                    for (size_t i = bytes_read; i < 16; i++) {
                        buffer[i] = padding_value;
                    }
                }
                aes_cipher(iv, key, output, key_size);
                xor_blocks(output, buffer);
                memcpy(iv, output, 16);
                fwrite(output, 1, 16, out_file);
            }

            // Padding d'un bloc entier si multiple de 16
            if (feof(in_file) && last_bytes_read == 16) {
                for (int i = 0; i < 16; i ++) {
                    buffer[i] = 16;
                }
                aes_cipher(iv, key, output, key_size);
                xor_blocks(output, buffer);
                memcpy(iv, output, 16);
                fwrite(output, 1, 16, out_file);

                fwrite(output, 1, 16, out_file);
            }
        } else if (mode == MODE_OFB) {
            // --- CHIFFREMENT OFB ---
            while ((bytes_read = fread(buffer, 1, 16, in_file)) > 0) {
                last_bytes_read = bytes_read; // On mémorise la taille lue
                if (bytes_read < 16) {
                    // Bloc incomplet : On va appliquer du Padding PKCS#7
                    uint8_t padding_value = 16 - bytes_read;
                    for (size_t i = bytes_read; i < 16; i++) {
                        buffer[i] = padding_value;
                    }
                }
                aes_cipher(iv, key, output, key_size);
                memcpy(iv, output, 16);
                xor_blocks(output, buffer);
                fwrite(output, 1, 16, out_file);
            }

            // Padding d'un bloc entier si multiple de 16
            if (feof(in_file) && last_bytes_read == 16) {
                for (int i = 0; i < 16; i ++) {
                    buffer[i] = 16;
                }
                aes_cipher(iv, key, output, key_size);
                memcpy(iv, output, 16);
                xor_blocks(output, buffer);
                fwrite(output, 1, 16, out_file);
            }
        }
    } else {
        // ==========================================
        //              DECHIFFREMENT
        // ==========================================
        uint8_t next_buffer[16];

        // On lit le 1er bloc
        bytes_read = fread(buffer, 1, 16, in_file);

        if (mode == MODE_ECB) {
            // --- DECHIFFREMENT ECB ---
            while (bytes_read == 16) {
                // On déchiffre le bloc courant
                aes_decipher(buffer, key, output, key_size);

                // On essaie de lire le bloc SUIVANT
                bytes_read = fread(next_buffer, 1, 16, in_file);

                if (bytes_read == 0) {
                    // C'est le dernier bloc ! On doit retirer le padding PKCS#7
                    uint8_t pad_val = output[15];

                    if (pad_val >= 1 && pad_val <= 16) {
                        // VÉRIFICATION STRICTE DU PADDING
                        bool valid_padding = true;
                        for (int i = 16 - pad_val; i < 16; i++) {
                            if (output[i] != pad_val) {
                                valid_padding = false;
                                break;
                            }
                        }
                        if (valid_padding) {
                            fwrite(output, 1, 16 - pad_val, out_file);
                        } else {
                            fprintf(stderr, "\nAvertissement : Padding PKCS#7 invalide détecté.\n");
                            fwrite(output, 1, 16, out_file);
                        }
                    } else {
                        fprintf(stderr, "\nAvertissement : Padding PKCS#7 invalide détecté.\n");
                        fwrite(output, 1, 16, out_file);
                    }
                } else {
                    // Ce n'est pas le dernier bloc, on écrit les 16 octets complets
                    fwrite(output, 1, 16, out_file);
                    memcpy(buffer, next_buffer, 16);
                }
            }
        } else if (mode == MODE_CBC) {
            // --- DECHIFFREMENT CBC ---
            uint8_t temp_iv[16];    // Nouveau tableau temporaire

            while (bytes_read == 16) {
                // On sauvegarde le bloc chiffré ACTUEL avant de le déchiffrer !
                memcpy(temp_iv, buffer, 16);
                
                // On déchiffre le bloc courant
                aes_decipher(buffer, key, output, key_size);
                // XOR avec l'IV pour retrouver le texte clair
                xor_blocks(output, iv);
                // Le buffer devient l'IV du tour suivant
                memcpy(iv, temp_iv, 16);

                bytes_read = fread(next_buffer, 1, 16, in_file);

                if (bytes_read == 0) {
                    // C'est le dernier bloc ! On doit retirer le padding PKCS#7
                    uint8_t pad_val = output[15];

                    if (pad_val >= 1 && pad_val <= 16) {
                        // VÉRIFICATION STRICTE DU PADDING
                        bool valid_padding = true;
                        for (int i = 16 - pad_val; i < 16; i++) {
                            if (output[i] != pad_val) {
                                valid_padding = false;
                                break;
                            }
                        }
                        if (valid_padding) {
                            fwrite(output, 1, 16 - pad_val, out_file);
                        } else {
                            fprintf(stderr, "\nAvertissement : Padding PKCS#7 invalide détecté.\n");
                            fwrite(output, 1, 16, out_file);
                        }
                    } else {
                        fprintf(stderr, "\nAvertissement : Padding PKCS#7 invalide détecté.\n");
                        fwrite(output, 1, 16, out_file);
                    }
                } else {
                    // Ce n'est pas le dernier bloc, on écrit les 16 octets complets
                    fwrite(output, 1, 16, out_file);
                    memcpy(buffer, next_buffer, 16);
                }
            }
        } else if (mode == MODE_CFB) {
            // --- DECHIFFREMENT CFB ---
            uint8_t temp_iv[16];

            while (bytes_read == 16) {

                // On sauvegarde le bloc chiffré courant
                memcpy(temp_iv, buffer, 16);

                // On utilise aes_cipher même pour déchiffrer
                aes_cipher(iv, key, output, key_size);

                // XOR avec le texte chiffré pour retrouver le clair
                xor_blocks(output, buffer);

                // L'ancien texte chiffré devient le nouvel IV
                memcpy(iv, temp_iv, 16);
                bytes_read = fread(next_buffer, 1, 16, in_file);

                if (bytes_read == 0) {
                    // C'est le dernier bloc ! On doit retirer le padding PKCS#7
                    uint8_t pad_val = output[15];

                    if (pad_val >= 1 && pad_val <= 16) {
                        // VÉRIFICATION STRICTE DU PADDING
                        bool valid_padding = true;
                        for (int i = 16 - pad_val; i < 16; i++) {
                            if (output[i] != pad_val) {
                                valid_padding = false;
                                break;
                            }
                        }
                        if (valid_padding) {
                            fwrite(output, 1, 16 - pad_val, out_file);
                        } else {
                            fprintf(stderr, "\nAvertissement : Padding PKCS#7 invalide détecté.\n");
                            fwrite(output, 1, 16, out_file);
                        }
                    } else {
                        fprintf(stderr, "\nAvertissement : Padding PKCS#7 invalide détecté.\n");
                        fwrite(output, 1, 16, out_file);
                    }
                } else {
                    // Ce n'est pas le dernier bloc, on écrit les 16 octets complets
                    fwrite(output, 1, 16, out_file);
                    memcpy(buffer, next_buffer, 16);
                }
            }
        } else if (mode == MODE_OFB) {
            // --- DECHIFFREMENT OFB ---
            while (bytes_read == 16) {

                aes_cipher(iv, key, output, key_size);
                memcpy(iv, output, 16);
                xor_blocks(output, buffer);

                bytes_read = fread(next_buffer, 1, 16, in_file);

                if (bytes_read == 0) {
                    // C'est le dernier bloc ! On doit retirer le padding PKCS#7
                    uint8_t pad_val = output[15];

                    if (pad_val >= 1 && pad_val <= 16) {
                        // VÉRIFICATION STRICTE DU PADDING
                        bool valid_padding = true;
                        for (int i = 16 - pad_val; i < 16; i++) {
                            if (output[i] != pad_val) {
                                valid_padding = false;
                                break;
                            }
                        }
                        if (valid_padding) {
                            fwrite(output, 1, 16 - pad_val, out_file);
                        } else {
                            fprintf(stderr, "\nAvertissement : Padding PKCS#7 invalide détecté.\n");
                            fwrite(output, 1, 16, out_file);
                        }
                    } else {
                        fprintf(stderr, "\nAvertissement : Padding PKCS#7 invalide détecté.\n");
                        fwrite(output, 1, 16, out_file);
                    }
                } else {
                    // Ce n'est pas le dernier bloc, on écrit les 16 octets complets
                    fwrite(output, 1, 16, out_file);
                    memcpy(buffer, next_buffer, 16);
                }
            }
        }
    }
}

// Fonction utilitaire pour afficher un bloc de 16 octets
void print_block(const char* label, const uint8_t block[16]) {
    printf("%s : ", label);
    for (int i = 0; i < 16; i++) {
        printf("%02x ", block[i]);
    }
    printf("\n");
}

void test_gcm_math() {
    printf("\n=== DEBUT DES TESTS GCM ===\n");
    // ---------------------------------------------------------
    // TEST 1 : increment_compteur
    // ---------------------------------------------------------
    printf("\n--- Test 1 : Increment Compteur ---\n");
    uint8_t counter[16] = {
        0xAA, 0xBB, 0xCC, 0xDD, 0x00, 0x00, 0x00, 0x00,  // 96 bits de gauche (intouchables)
        0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFE   // 32 bits de droite
    };
    print_block("Avant      ", counter);
    increment_compteur(counter);
    print_block("Après (+1) ", counter);
    increment_compteur(counter);
    print_block("Après (+2) ", counter); 
    // Le résultat attendu doit finir par ... 00 00 00 00 (la retenue work)

    // ---------------------------------------------------------
    // TEST 2 : gcm_mult
    // ---------------------------------------------------------
    printf("\n--- Test 2 : Multiplication de Galois ---\n");
    // H = une sous-clé aléatoire
    uint8_t H[16] = {
        0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b,
        0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34, 0x2b, 0x2e
    };
    // L'élément neutre "1" dans GF(2^128) tel que défini par le NIST
    uint8_t identity[16] = {
        0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    uint8_t Z[16] = {0};
    
    print_block("Valeur de H", H);
    gcm_mult(H, identity, Z);
    print_block("H * 1      ", Z);
    // Le résultat attendu doit être EXACTEMENT identique à H !

    // ---------------------------------------------------------
    // TEST 3 : ghash 
    // ---------------------------------------------------------
    printf("\n--- Test 3 : Compression GHASH ---\n");
    uint8_t data_to_hash[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // Bloc 1
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, // Bloc 2
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
    };
    uint8_t hash_out[16];
    ghash(H, data_to_hash, 32, hash_out);
    print_block("GHASH Out  ", hash_out);
    // On vérifie juste que ça calcule une empreinte sans erreur mémoire.
    
    printf("=== FIN DES TESTS ===\n\n");
}

// Test pour visualiser le piège Little-Endian vs Big-Endian
void test_endianness() {
    printf("\n=== DEBUT DU TEST ENDIANNESS ===\n");

    // Notre nombre de 64 bits (8 octets)
    uint64_t val = 0x1122334455667788;

    uint8_t buffer_memoire[8]   = {0};
    uint8_t buffer_gcm[8]       = {0};

    // 1. Copie en mémoire
    memcpy(buffer_memoire, &val, 8);

    // 2. Copie par notre fonction Big-Endian
    uint64_t val_temp = val;
    for (int i = 7; i >= 0; i--) {
        buffer_gcm[i] = (uint8_t)(val_temp & 0xFF);
        val_temp >>= 8;
    }

    // --- AFFICHAGE ---
    printf("Valeur d'origine (en hex) : 0x1122334455667788\n\n");

    printf("1. Copie brute (Little-Endian) :\n");
    printf("   -> ");
    for(int i = 0; i < 8; i++) {
        printf("%02x ", buffer_memoire[i]);
    }

    printf("\n2. Notre fonction (Big-Endian) :\n");
    printf("   -> ");
    for(int i = 0; i < 8; i++) {
        printf("%02x ", buffer_gcm[i]);
    }
    
    printf("=== FIN DU TEST ===\n\n");
}

int main(int argc, char *argv[]) {
    //test_endianness();
    //test_gcm_math();
    //return EXIT_SUCCESS;
    
    
    bool encrypting = true;                     // Par défaut, on chiffre
    AES_KEY_SIZE current_key_size = AES_128;    // 128 bits par défaut
    BLOCK_CIPHER_MODE current_mode = MODE_ECB;  // ECB par défaut

    char *key_hex_str = NULL;                   // Pour stocker la clé tapée en argument
    char *iv_hex_str = NULL;

    // Clé par défaut allouée sur 32 octets au cas où on force le 256 bits
    uint8_t current_key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Padding par défaut
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    uint8_t current_iv[16] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    };

    static struct option long_opts[] = {
        {"encrypt", no_argument,        0, 'e'},
        {"decrypt", no_argument,        0, 'd'},
        {"help",    no_argument,        0, 'h'},
        {"size",    required_argument,  0, 's'},
        {"key",     required_argument,  0, 'k'},
        {"mode",    required_argument,  0, 'm'},
        {"iv",      required_argument,  0, 'v'},
        {0,0,0,0}
    };

    int opt, idx;
    while ((opt = getopt_long(argc, argv, "edhk:s:m:v:", long_opts, &idx)) != -1) {
        switch (opt) {
            case 'e': encrypting = true; break; 
            case 'd': encrypting = false; break;
            case 'h': print_usage(stdout); return EXIT_SUCCESS;
            
            case 's': {
                int size_val = atoi(optarg);
                if (size_val == 128) {
                    current_key_size = AES_128;
                } else if (size_val == 192) {
                    current_key_size = AES_192;
                } else if (size_val == 256) {
                    current_key_size = AES_256;
                } else {
                    fprintf(stderr, "Erreur : La taille de la clé doit être 128, 192 ou 256.\n");
                    return EXIT_FAILURE;
                }
                break;
            }
            case 'k':
                key_hex_str = optarg;
                break;

            case 'm': {
                if (strcmp(optarg, "ecb") == 0) {
                    current_mode = MODE_ECB;
                } else if (strcmp(optarg, "cbc") == 0) {
                    current_mode = MODE_CBC;
                } else if (strcmp(optarg, "cfb") == 0) {
                    current_mode = MODE_CFB;
                } else if (strcmp(optarg, "ofb") == 0) {
                    current_mode = MODE_OFB;
                } else if (strcmp(optarg, "gcm") == 0) {
                    current_mode = MODE_GCM;
                }else {
                    fprintf(stderr, "Erreur : mode inconnu. Utiliser 'ecb', 'cbc', 'cfb', 'ofb' ou 'gcm'.\n");
                    return EXIT_FAILURE;
                }
                break;
            }   
            case 'v':
                iv_hex_str = optarg;
                break;

            default:
                print_usage(stderr);
                return EXIT_FAILURE;
        }
    }

    // Validation de la clé
    if (key_hex_str != NULL) {
        int expected_hex_len = current_key_size * 2;
        if (strlen(key_hex_str) != (size_t)expected_hex_len) {
            fprintf(stderr, "Erreur : Pour une clé AES-%d, la clé doit faire exactement %d caractères hexadécimaux.\n", current_key_size * 8, expected_hex_len);
            return EXIT_FAILURE;
        }
        // Conversion sécurisée
        hex_to_bytes(key_hex_str, current_key, current_key_size);
    }
    
    // Validation de l'IV 
    if (current_mode != MODE_ECB) {
        if (iv_hex_str == NULL) {
            printf("Info : Aucun IV fourni. Utilisation de l'IV par défaut.\n");
        } else {
            if (strlen(iv_hex_str) != 32) {
                fprintf(stderr, "Erreur : L'IV doit faire exactement 32 caractères hexadécimaux.\n");
                return EXIT_FAILURE;
            }
            hex_to_bytes(iv_hex_str, current_iv, 16);
        }
    }

    // Il nous faut exactement 2 arguments restants (fichier in et out)
    if (optind + 2 != argc) {
        fprintf(stderr, "Erreur : Fichier d'entrée ou de sortie manquants.\n");
        print_usage(stderr);
        return EXIT_FAILURE;
    }

    char *in_filename  = argv[optind];
    char *out_filename = argv[optind + 1];

    FILE *in_file = fopen(in_filename, "rb");
    if (!in_file) {
        perror("Erreur d'ouverture du fichier d'entrée");
        return EXIT_FAILURE;
    }

    FILE *out_file = fopen(out_filename, "wb");
    if (!out_file) {
        perror("Erreur de création du fichier de sortie");
        return EXIT_FAILURE;
    }

    // Traitement du fichier
    process_file(in_file, out_file, encrypting, current_key, current_key_size, current_mode, current_iv);

    const char* mode_str = "ECB";
    if (current_mode == MODE_CBC) mode_str = "CBC";
    if (current_mode == MODE_CFB) mode_str = "CFB";
    if (current_mode == MODE_OFB) mode_str = "OFB";
    if (current_mode == MODE_GCM) mode_str = "GCM";

    printf("Opération terminée avec succès (AES-%d %s).\n", current_key_size * 8, mode_str);
    
    fclose(in_file);
    fclose(out_file);
    return EXIT_SUCCESS;
}

