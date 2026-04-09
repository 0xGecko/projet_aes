#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <getopt.h>
#include "../include/aes.h"

// Clé par défaut démandé par la ROADMAP (0x00 à 0x0f
static const uint8_t DEFAULT_KEY[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

// Fonction permettant l'affichage de l'aide
static void print_usage(FILE *out) {
    fprintf(out, 
        "Utilisation : ./aes [OPTIONS] fichier_entree fichier_sortie\n"
        "Chiffre ou déchiffre un fichier en utilisant AES-128 (Mode ECB).\n\n"
        "Options :\n"
        "   -e, --encrypt   Chiffrer le fichier (Default)\n"
        "   -d, --decrypt   Déchiffrer le fichier\n"
        "   -h, --help      Affichage de l'aide\n"
        "   (La clé est fixé par défaut pour le moment)\n"
    );
}

// Fonction pour traiter le fichier (Chiffrement ECB avec Padding PKCS#7)
static void process_file(FILE *in_file, FILE *out_file, bool encrypting) {
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
                aes_cipher(buffer, DEFAULT_KEY, output);
                fwrite(output, 1, 16, out_file);
            } else {
                // Bloc incomplet : On va appliquer du Padding PKCS#7
                uint8_t padding_value = 16 - bytes_read;
                for (size_t i = bytes_read; i < 16; i++) {
                    buffer[i] = padding_value;
                }
                aes_cipher(buffer, DEFAULT_KEY, output);
                fwrite(output, 1, 16, out_file);
            }
        }

        // Remarque importante : Si le fichier tombe pile sur un multiple de 16,
        // il faut rajouter un bloc entier de padding (16 octets de valeur 16)
        if (feof(in_file) && last_bytes_read == 16) {
            for (int i = 0; i < 16; i ++) {
                buffer[i] = 16;
            }
            aes_cipher(buffer, DEFAULT_KEY, output);
            fwrite(output, 1, 16, out_file);
        }
    } else {
        // --- DECHIFFREMENT ---
        uint8_t next_buffer[16];

        // On lit le 1er bloc
        bytes_read = fread(buffer, 1, 16, in_file);

        while (bytes_read == 16) {
            // On déchiffre le bloc courant
            aes_decipher(buffer, DEFAULT_KEY, output);

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

int main(int argc, char *argv[]) {
    bool encrypting = true; // Par défaut, on chiffre

    static struct option long_opts[] = {
        {"encrypt", no_argument, 0, 'e'},
        {"decrypt", no_argument, 0, 'd'},
        {"help",    no_argument, 0, 'h'},
        {0,0,0,0}
    };

    int opt, idx;
    while ((opt = getopt_long(argc, argv, "edh", long_opts, &idx)) != -1) {
        switch (opt) {
            case 'e': 
                encrypting = true; 
                break; 

            case 'd':
                encrypting = false;
                break;

            case 'h':
                print_usage(stdout);
                return EXIT_SUCCESS;
            
            default:
                print_usage(stderr);
                return EXIT_FAILURE;
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
    process_file(in_file, out_file, encrypting);

    printf("Opération terminé avec succès.\n");

    fclose(in_file);
    fclose(out_file);
    return EXIT_SUCCESS;
}

