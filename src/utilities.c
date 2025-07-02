#include "cypher.h"

void invert_key(char range_low, char range_high, const char *key, char *inverted_key, size_t key_len)
{
    int range_size = range_high - range_low + 1;

    for (size_t i = 0; i < key_len; i++)
    {
        if (key[i] >= range_low && key[i] <= range_high)
        {
            int key_char_pos = key[i] - range_low;
            inverted_key[i] = (char)(range_low + (range_size - key_char_pos) % range_size);
        }
    }

    inverted_key[key_len] = '\0';
}

int cli(int argc, char **argv)
{
    if (argc != 4)
    {
        fprintf(stderr, "Usage: %s <operation> <key> <message>\n", argv[0]);
        return 1;
    }

    const char *operation = argv[1];
    const char *keyText = argv[2];
    const char *input_message = argv[3];

    if (strcmp(operation, "caesar-encrypt") != 0 &&
        strcmp(operation, "caesar-decrypt") != 0 &&
        strcmp(operation, "vigenere-encrypt") != 0 &&
        strcmp(operation, "vigenere-decrypt") != 0)
    {
        fprintf(stderr, "Error: %s is an invalid operation, must use one of 'caesar-encrypt', 'caesar-decrypt', 'vigenere-encrypt', or 'vigenere-decrypt'.\n", operation);
        return 1;
    }

    if ((strcmp(operation, "caesar-encrypt") == 0 || strcmp(operation, "caesar-decrypt") == 0))
    {
        char *endPtr;
        long int key = strtol(keyText, &endPtr, 10);
        if (*endPtr != '\0')
        {
            fprintf(stderr, "Error: Invalid integer key.\n");
            return 1;
        }
        if (key < INT_MIN || key > INT_MAX)
        {
            fprintf(stderr, "Error: Integer key is out of range.\n");
            return 1;
        }
    }
    else if (keyText[0] == '\0')
    {
        fprintf(stderr, "Error: Key is empty string.\n");
        return 1;
    }
    else
    {
        for (size_t i = 0; keyText[i] != '\0'; i++)
        {
            if (keyText[i] < 'A' || keyText[i] > 'Z')
            {
                fprintf(stderr, "Error: Key contains invalid characters for range 'A' - 'Z'.\n");
                return 1;
            }
        }
    }

    if (input_message[0] == '\0')
    {
        fprintf(stderr, "Error: Input message is an empty string.\n");
        return 1;
    }

    size_t input_length = strlen(input_message);
    char *output_message = (char *)malloc(input_length + 1);

    if (output_message == NULL)
    {
        fprintf(stderr, "Error: Memory allocation for output message failed.\n");
        return 1;
    }

    if (strcmp(operation, "caesar-encrypt") == 0 || strcmp(operation, "caesar-decrypt") == 0)
    {
        int caesar_key = (int)strtol(keyText, NULL, 10);
        if (strcmp(operation, "caesar-encrypt") == 0)
        {
            caesar_encrypt('A', 'Z', caesar_key, input_message, output_message);
        }
        else
        {
            caesar_decrypt('A', 'Z', caesar_key, input_message, output_message);
        }
    }
    else
    {
        if (strcmp(operation, "vigenere-encrypt") == 0)
        {
            vigenere_encrypt('A', 'Z', keyText, input_message, output_message);
        }
        else
        {
            vigenere_decrypt('A', 'Z', keyText, input_message, output_message);
        }
    }

    printf("%s\n", output_message);
    free(output_message);
    return 0;
}