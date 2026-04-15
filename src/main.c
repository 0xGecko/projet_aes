#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <getopt.h>
#include "../include/aes.h"

// Fonction permettant l'affichage de l'aide
static void print_usage(FILE *out) {
    fprintf(out, 
        "Utilisation : ./aes [OPTIONS] fichier_entree fichier_sortie\n"
        "Chiffre ou déchiffre un fichier en utilisant AES-128 (Mode ECB).\n\n"
        "Options :\n"
        "   -e, --encrypt   Chiffrer le fichier (Default)\n"
        "   -d, --decrypt   Déchiffrer le fichier\n"
        "   -h, --help      Affichage de l'aide\n"
        "   -s, --size,     Taille de la clé en bits : 128 (défaut), 192 ou 256\n"
        "   -k, --key,      Spécifier une clé en héxadécimal (32 caractères).\n"
    );
}

// Fonction pour traiter le fichier (Chiffrement ECB avec Padding PKCS#7)
static void process_file(FILE *in_file, FILE *out_file, bool encrypting, const uint8_t *key, AES_KEY_SIZE key_size) {
    uint8_t buffer[16];
    uint8_t output[16];
    size_t bytes_read;
    size_t last_bytes_read = 0; 

    if (encrypting) {
        // --- CHIFFREMENT ---
        while ((bytes_read = fread(buffer, 1, 16, in_file)) > 0) {
            last_bytes_read = bytes_read; // On mémorise la taille lue
            if (bytes_read == 16) {
                // Bloc complet de 16 octets
                aes_cipher(buffer, key, output, key_size);
                fwrite(output, 1, 16, out_file);
            } else {
                // Bloc incomplet : On va appliquer du Padding PKCS#7
                uint8_t padding_value = 16 - bytes_read;
                for (size_t i = bytes_read; i < 16; i++) {
                    buffer[i] = padding_value;
                }
                aes_cipher(buffer, key, output, key_size);
                fwrite(output, 1, 16, out_file);
            }
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
    } else {
        // --- DECHIFFREMENT ---
        uint8_t next_buffer[16];

        // On lit le 1er bloc
        bytes_read = fread(buffer, 1, 16, in_file);

        while (bytes_read == 16) {
            // On déchiffre le bloc courant
            aes_decipher(buffer, key, output, key_size);

            // On essaie de lire le bloc SUIVANT
            bytes_read = fread(next_buffer, 1, 16, in_file);

            if (bytes_read == 0) {
                // C'est le dernier bloc ! On doit retirer le padding PKCS#7
                uint8_t pad_val = output[15];

                // On vérifie que notre padding est compris entre 1 et 16
                if (pad_val >= 1 && pad_val <= 16) {
                    fwrite(output, 1, 16 - pad_val, out_file);
                } else {
                    fprintf(stderr, "Avertissement : Padding PKCS#7 invalide détecté.\n");
                    fwrite(output, 1, 16, out_file);
                }
            } else {
                // Ce n'est pas le dernier bloc, on écrit les 16 octets complets
                fwrite(output, 1, 16, out_file);

                for (int i = 0; i < 16; i++) {
                    buffer[i] = next_buffer[i];
                }
            }

        }
    }
}

// Fonction sécurisée pour la conversion de la clé
void hex_to_bytes(const char* hex, uint8_t* bytes, int byte_len) {
    for (int i = 0; i < byte_len; i++) {
        unsigned int temp_val;
        sscanf(hex + 2 * i, "%2x", &temp_val);
        bytes[i] = (uint8_t)temp_val;
    }
}

int main(int argc, char *argv[]) {
    bool encrypting = true;                     // Par défaut, on chiffre
    AES_KEY_SIZE current_key_size = AES_128;    // 128 bits par défaut
    char *key_hex_str = NULL;                   // Pour stocker la clé tapée en argument

    // Clé par défaut allouée sur 32 octets au cas où on force le 256 bits
    uint8_t current_key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Padding par défaut
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    static struct option long_opts[] = {
        {"encrypt", no_argument,        0, 'e'},
        {"decrypt", no_argument,        0, 'd'},
        {"help",    no_argument,        0, 'h'},
        {"size",    required_argument,  0, 's'},
        {"key",     required_argument,  0, 'k'},
        {0,0,0,0}
    };

    int opt, idx;
    while ((opt = getopt_long(argc, argv, "edhk:s:", long_opts, &idx)) != -1) {
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
                key_hex_str = optarg; // On sauvegarde la chaîne pour plus tard
                break;

            default:
                print_usage(stderr);
                return EXIT_FAILURE;
        }
    }

    // Validation de la longueur de la clé APRÈS avoir défini la taille
    if (key_hex_str != NULL) {
        int expected_hex_len = current_key_size * 2;
        if (strlen(key_hex_str) != (size_t)expected_hex_len) {
            fprintf(stderr, "Erreur : Pour une clé AES-%d, la clé doit faire exactement %d caractères hexadécimaux.\n", current_key_size * 8, expected_hex_len);
            return EXIT_FAILURE;
        }
        // Conversion sécurisée
        hex_to_bytes(key_hex_str, current_key, current_key_size);
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
    process_file(in_file, out_file, encrypting, current_key, current_key_size);

    printf("Opération terminée avec succès (Mode: AES-%d ECB).\n", current_key_size * 8);

    fclose(in_file);
    fclose(out_file);
    return EXIT_SUCCESS;
}

