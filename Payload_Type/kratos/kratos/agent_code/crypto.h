#ifndef KRATOS_CRYPTO_H
#define KRATOS_CRYPTO_H

#define _WIN32_WINNT 0x0600
/* clang-format off */
/* CRITICAL ORDER: windows.h must precede bcrypt.h
 * Do not let the formatter reorder these two lines. */
#include <windows.h>
#include <bcrypt.h>
/* clang-format on */

#include <stddef.h>

/*
 * Mythic AES256 format:
 *   IV (16 bytes) | AES-256-CBC(plaintext) | HMAC-SHA256(IV + ciphertext) (32
 * bytes)
 *
 * aes_key must be 32 raw bytes.
 */

/*
 * aes256_encrypt
 *
 * Encrypts `plaintext` (len `plain_len`) with key `aes_key` (32 bytes).
 * Alloue et retourne le buffer: IV + Ciphertext + HMAC
 * *out_len receives the size of the returned buffer.
 * Returns NULL on error. Caller must free() the result.
 */
unsigned char *aes256_encrypt(const unsigned char *aes_key,
                              const unsigned char *plaintext, size_t plain_len,
                              size_t *out_len);

/*
 * aes256_decrypt
 *
 * Decrypts `cipherblob` (layout: IV + Ciphertext + HMAC) of size `blob_len`.
 * Verifies HMAC before decrypting.
 * Returns a malloc'd buffer (plaintext, null-terminated), or NULL on error/HMAC
 * invalid. *out_len receives the plaintext length (without trailing \0).
 */
unsigned char *aes256_decrypt(const unsigned char *aes_key,
                              const unsigned char *cipherblob, size_t blob_len,
                              size_t *out_len);

/*
 * crypto_init_key
 *
 * Decodes the AESPSK key from its base64 representation to raw memory (32
 * bytes). `b64_key`  : string base64 (telle que fournie par config.h) `key_out`
 * : 32-byte buffer provided by the caller. Returns 1 on success, 0 on failure
 * (invalid key, "none" mode, etc.)
 */
int crypto_init_key(const char *b64_key, unsigned char key_out[32]);

#endif /* KRATOS_CRYPTO_H */
