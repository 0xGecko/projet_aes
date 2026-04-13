CC = gcc
CFLAGS = -Wall -Wextra -O3 -Iinclude

# L'exécutable principal (pour le projet)
TARGET = aes
# L'exécutable de test
TEST_TARGET = tests/test_aes

# Les fichiers sources
SRC_AES = src/aes.c
SRC_MAIN = src/main.c
SRC_TEST = tests/test_aes.c

# Les fichiers objets correspondants
OBJ_AES = $(SRC_AES:.c=.o)
OBJ_MAIN = $(SRC_MAIN:.c=.o)
OBJ_TEST = $(SRC_TEST:.c=.o)

all: $(TARGET) $(TEST_TARGET)

# Règle pour compiler le programme principal
$(TARGET): $(OBJ_AES) $(OBJ_MAIN)
	$(CC) $(CFLAGS) -o $@ $^

# Règle pour compiler les tests
$(TEST_TARGET): $(OBJ_AES) $(OBJ_TEST)
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f src/*.o tests/*.o $(TARGET) $(TEST_TARGET)