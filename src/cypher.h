#ifndef CRYPTO_H
#define CRYPTO_H

// Headers
#include <stddef.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <assert.h>

/** Encrypt a given plaintext using the Caesar cipher, using a specified key, where the
 * characters to encrypt fall within a given range (and all other characters are copied
 * over unchanged).
 *
 * Each character in `plain_text` is examined to see if it falls with the range specified
 * by `range_low` and `range_high`, and a corresponding character is then written to the
 * same position in `cipher_text`. If the `plain_text` character is outside the range,
 * then the corresponding character is not encrypted: exactly the same character should
 * be written to exactly the same position in `cipher_text`. If the `plain_text`
 * character is within the range, it should be encrypted using the Caesar cipher:
 * a new character is obtained by shifting it by `key` positions (modulo the size of the
 * range).
 *
 * For decryption, use a negative key value or use the `caesar_decrypt` function with the
 * same key value.
 *
 *
 * ## Example usage
 *
 *
 *
 * ```c
 *   char plain_text[] = "HELLOWORLD";
 *   char cipher_text[sizeof(plain_text)] = {0};
 *   caesar_encrypt('A', 'Z', 3, plain_text, cipher_text);
 *   // After the function call, cipher_text will contain the encrypted text
 *   char expected_cipher_text = "KHOORZRUOG"
 *   assert(strcmp(cipher_text, expected_cipher_text) == 0);
 * ```
 *
 * \param range_low A character representing the lower bound of the character range to be
 *           encrypted
 * \param range_high A character representing the upper bound of the character range
 * \param key The encryption key
 * \param plain_text A null-terminated string containing the plaintext to be encrypted
 * \param cipher_text A pointer to a buffer where the encrypted text will be stored. The
 *           buffer must be large enough to hold a C string of the same length as
 *           plain_text (including the terminating null character).
 *
 * \pre `plain_text` must be a valid null-terminated C string
 * \pre `cipher_text` must point to a buffer of identical length to `plain_text`
 * \pre `range_high` must be strictly greater than `range_low`.
 * \pre `key` must fall within the range from `(range_low - range_high)` to
 *      `(range_high - range_low)`, inclusive.
 */
void caesar_encrypt(char range_low, char range_high, int key, const char *plain_text, char *cipher_text);

/** Decrypt a given ciphertext using the Caesar cipher, using a specified key, where the
 * characters to decrypt fall within a given range (and all other characters are copied
 * over unchanged).
 *
 * Calling `caesar_decrypt` with some key n is exactly equivalent to calling
 * `caesar_encrypt` with the key -n.
 *
 * \param range_low A character representing the lower bound of the character range to be
 *           encrypted
 * \param range_high A character representing the upper bound of the character range
 * \param key The encryption key
 * \param cipher_text A null-terminated string containing the ciphertext to be decrypted
 * \param plain_text A pointer to a buffer where the decrypted text will be stored. The
 *           buffer must be large enough to hold a C string of the same length as
 *           cipher_text (including the terminating null character).
 *
 * \pre `cipher_text` must be a valid null-terminated C string
 * \pre `plain_text` must point to a buffer of identical length to `cipher_text`
 * \pre `range_high` must be strictly greater than `range_low`.
 * \pre `key` must fall within range from `(range_low - range_high)` to
 *      `(range_high - range_low)`, inclusive.
 */
void caesar_decrypt(char range_low, char range_high, int key, const char *cipher_text, char *plain_text);

/** Encrypt a given plaintext using the Vigenere cipher, using a specified key, where the
 * characters to encrypt fall within a given range (and all other characters are copied
 * over unchanged).
 *
 * Each character in `plain_text` is examined to see if it falls with the range specified
 * by `range_low` and `range_high`, and a corresponding character is then written to the
 * same position in `cipher_text`. If the `plain_text` character is outside the range,
 * then the corresponding character is not encrypted: exactly the same character should
 * be written to exactly the same position in `cipher_text`. If the `plain_text`
 * character is within the range, it should be encrypted using the Vigenere cipher.
 * The function maintains an index into `key`, and uses the "current key character"
 * to encrypt. This index starts at position 0, and increments whenever an in-range
 * plaintext character is encountered. (In other words, out-of-range characters do
 * not result in a change of Caesar cipher.)
 *
 * \param range_low A character representing the lower bound of the character range to be
 *           encrypted
 * \param range_high A character representing the upper bound of the character range
 * \param key A null-terminated string containing the encryption key
 * \param plain_text A null-terminated string containing the plaintext to be encrypted
 * \param cipher_text A pointer to a buffer where the encrypted text will be stored. The
 *           buffer must be large enough to hold a C string of the same length as
 *           plain_text (including the terminating null character).
 *
 * \pre `plain_text` must be a valid null-terminated C string
 * \pre `cipher_text` must point to a buffer of identical length to `plain_text`
 * \pre `range_high` must be strictly greater than `range_low`.
 * \pre `key` must not be an empty string, and all characters in `key` must be within
 *        the range from `range_low` to `range_high` (inclusive).
 */
void vigenere_encrypt(char range_low, char range_high, const char *key,
                      const char *plain_text, char *cipher_text);

/** Decrypt a given ciphertext using the Vigenere cipher, using a specified key, where the
 * characters to decrypt fall within a given range (and all other characters are copied
 * over unchanged).
 *
 * Calling `vigenere_decrypt` with some key $k$ should exactly reverse the operation of
 * `vigenere_encrypt` when called with the same key.
 *
 * \param range_low A character representing the lower bound of the character range to be
 *           decrypted
 * \param range_high A character representing the upper bound of the character range
 * \param key A null-terminated string containing the encryption key
 * \param cipher_text A null-terminated string containing the ciphertext to be decrypted
 * \param plain_text A pointer to a buffer where the decrypted text will be stored. The
 *           buffer must be large enough to hold a C string of the same length as
 *           cipher_text (including the terminating null character).
 *
 * \pre `cipher_text` must be a valid null-terminated C string
 * \pre `plain_text` must point to a buffer of identical length to `cipher_text`
 * \pre `range_high` must be strictly greater than `range_low`.
 * \pre `key` must not be an empty string, and all characters in `key` must be within
 *        the range from `range_low` to `range_high` (inclusive).
 */
void vigenere_decrypt(char range_low, char range_high, const char *key,
                      const char *cipher_text, char *plain_text);

/**
 * CLI function to encrypt or decrypt a message using Caesar or Vigenere cipher, for the range 'A'-'Z'.
 *
 * This function performs encryption or decryption based on the provided arguments.
 * It supports the following operations:
 * - "caesar-encrypt": Encrypts the message using Caesar cipher with the provided integer key.
 * - "caesar-decrypt": Decrypts the message using Caesar cipher with the provided integer key.
 * - "vigenere-encrypt": Encrypts the message using Vigenere cipher with the provided string key.
 * - "vigenere-decrypt": Decrypts the message using Vigenere cipher with the provided string key.
 *
 * Example usage: ./exe caesar-encrypt 5 "HELLO WORLD"
 *
 * The function checks for the correct number of arguments and validates the key based on the operation.
 * If any error occurs an appropriate error message is printed to standard error, and the function returns 1.
 * On success, it prints the encrypted or decrypted message to standard output followed by a newline and returns 0.
 *
 * @param argc The number of command-line arguments.
 * @param argv An array of command-line arguments.
 * @return 0 on success, 1 on failure.
 * \pre `argc` must be 4.
 * \pre `argv` must contain valid strings for the operation, key, and message.
 * \pre any message containing special characters (EG, '$' or '`') must have their special meaning escaped by the user
 */
int cli(int argc, char **argv);

/**
 * Helper function to invert a key used for Vigenere encryption to be used decryption.
 *
 * This function takes the original encryption key to make a new inverted key such that each character in the adjusted key
 * represents the inverse shift of the corresponding character in the original key.
 * The adjusted key is such that encrypting with this new key is equivalent to the reverse operation of
 * `vigenere_encrypt` called with the original key.
 *
 *
 * @param range_low A character representing the lower bound of the character range. nhjuj
 * @param range_high A character representing the upper bound of the character range.
 * @param key The original encryption key.
 * @param inverted_key The buffer to store the adjusted decryption key (output). Must be at least `key_len + 1` bytes.
 * @param key_len The length of the original key.
 *
 * \pre `range_high` must be strictly greater than `range_low`.
 * \pre `key` must not be an empty string, and all characters in `key` must be within the range from `range_low` to `range_high` (inclusive).
 * \pre `inverted_key` must point to a buffer of at least `key_len + 1` bytes.
 */
void invert_key(char range_low, char range_high, const char *key, char *inverted_key, size_t key_len);

#endif // CRYPTO_H
