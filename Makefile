# Compilateur et options
CC = gcc
CFLAGS = -Wall -Wextra -g -Iinclude

# Dossiers
SRC_DIR = src
TEST_DIR = tests

# Fichiers sources et objets
SRC = $(SRC_DIR)/aes.c
OBJ = $(SRC:.c=.o)

TEST_SRC = $(TEST_DIR)/test_aes.c
TEST_OBJ = $(TEST_SRC:.c=.o)

# Nom de l'exécutable de test
TEST_EXEC = $(TEST_DIR)/test_aes

# Règle par défaut
all: test

# Compilation de l'exécutable de test
test: $(OBJ) $(TEST_OBJ)
	$(CC) $(CFLAGS) -o $(TEST_EXEC) $(OBJ) $(TEST_OBJ)

# Règle générique pour compiler les .c en .o
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Nettoyage des fichiers compilés
clean:
	rm -f $(SRC_DIR)/*.o $(TEST_DIR)/*.o $(TEST_EXEC)

.PHONY: all test clean