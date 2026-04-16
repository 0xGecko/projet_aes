#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <getopt.h>
#include "../include/aes.h"

// Définitions des modes d'opérations supportés
typedef enum {
    MODE_ECB,
    MODE_CBC
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
        "   -m, --mode,     Mode d'opéraions : ECB (défaut), CBC\n"
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

/* Fonction utilitaire : xor_blocks
-----------------------------------
Applique XOR entre deux blocks de 16 octets
*/
void xor_blocks(uint8_t *dest, uint8_t *src) {
    for (int i = 0; i < 16; i++) {
        dest[i] ^= src[i];
    }
}

// Fonction pour traiter le fichier (Chiffrement ECB ou CBC avec Padding PKCS#7)
static void process_file(FILE *in_file, FILE *out_file, bool encrypting, const uint8_t *key, AES_KEY_SIZE key_size, BLOCK_CIPHER_MODE mode, uint8_t *iv) {
    uint8_t buffer[16];
    uint8_t output[16];
    size_t bytes_read;
    size_t last_bytes_read = 0; 

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
        }
    }
}

int main(int argc, char *argv[]) {
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
                } else {
                    fprintf(stderr, "Erreur : mode inconnu. Utiliser 'ecb' ou 'cbc'.\n");
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
    if (current_mode == MODE_CBC) {
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

    printf("Opération terminée avec succès (AES-%d %s).\n", current_key_size * 8, current_mode == MODE_ECB ? "ECB" : "CBC");
    
    fclose(in_file);
    fclose(out_file);
    return EXIT_SUCCESS;
}

