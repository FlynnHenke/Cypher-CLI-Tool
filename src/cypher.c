#include "cypher.h"

void caesar_encrypt(char range_low, char range_high, int key,
                    const char *plain_text, char *cipher_text)
{
    assert(plain_text != NULL && cipher_text != NULL);
    assert(range_high > range_low);

    // Make key positive and in valid range
    int range_size = range_high - range_low + 1;
    key = ((key % range_size) + range_size) % range_size;

    assert(key >= 0 && key < range_size);

    while (*plain_text != '\0')
    {
        if (*plain_text >= range_low && *plain_text <= range_high)
        {
            // caesar encryption formula
            *cipher_text = (char)(range_low + ((*plain_text - range_low + key) % range_size));
        }
        else
        {
            *cipher_text = *plain_text;
        }
        plain_text++;
        cipher_text++;
    }

    *cipher_text = '\0';
}

void caesar_decrypt(char range_low, char range_high, int key,
                    const char *cipher_text, char *plain_text)
{
    caesar_encrypt(range_low, range_high, -key, cipher_text, plain_text);
}

void vigenere_encrypt(char range_low, char range_high, const char *key,
                      const char *plain_text, char *cipher_text)
{

    assert(plain_text != NULL && cipher_text != NULL);
    assert(key != NULL && key[0] != '\0');
    assert(range_high > range_low);

    size_t key_index = 0;
    size_t key_len = strlen(key);

    printf("    THE KEY: %s.\n", key);

    while (*plain_text != '\0')
    {
        if (*plain_text >= range_low && *plain_text <= range_high)
        {
            int key_char = key[key_index] - range_low;
            caesar_encrypt(range_low, range_high, key_char, plain_text, cipher_text);
            key_index = (key_index + 1) % key_len;
        }
        else
        {
            *cipher_text = *plain_text;
        }

        plain_text++;
        cipher_text++;
    }

    *cipher_text = '\0';
}

void vigenere_decrypt(char range_low, char range_high, const char *key,
                      const char *cipher_text, char *plain_text)
{

    assert(plain_text != NULL && cipher_text != NULL);
    assert(key != NULL && key[0] != '\0');
    assert(range_high > range_low);

    size_t key_len = strlen(key);
    char inverted_key[key_len + 1];

    invert_key(range_low, range_high, key, inverted_key, key_len);

    vigenere_encrypt(range_low, range_high, inverted_key, cipher_text, plain_text);
}
