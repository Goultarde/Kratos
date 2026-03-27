#ifndef KRATOS_CRYPTO_H
#define KRATOS_CRYPTO_H

#define _WIN32_WINNT 0x0600
/* clang-format off */
/* ORDRE CRITIQUE: windows.h doit précéder bcrypt.h
 * Ne pas laisser le formatter réordonner ces deux lignes. */
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
 * Chiffre `plaintext` (len `plain_len`) avec la clé `aes_key` (32 bytes).
 * Alloue et retourne le buffer: IV + Ciphertext + HMAC
 * *out_len reçoit la taille du buffer retourné.
 * Retourne NULL en cas d'erreur. Le caller doit free() le résultat.
 */
unsigned char *aes256_encrypt(const unsigned char *aes_key,
                              const unsigned char *plaintext, size_t plain_len,
                              size_t *out_len);

/*
 * aes256_decrypt
 *
 * Déchiffre `cipherblob` (layout: IV + Ciphertext + HMAC) de taille `blob_len`.
 * Vérifie le HMAC avant de déchiffrer.
 * Retourne un buffer malloc'd (plaintext, null-terminé), ou NULL si erreur/HMAC
 * invalide. *out_len reçoit la longueur du plaintext (sans le \0 final).
 */
unsigned char *aes256_decrypt(const unsigned char *aes_key,
                              const unsigned char *cipherblob, size_t blob_len,
                              size_t *out_len);

/*
 * crypto_init_key
 *
 * Décode la clé AESPSK depuis sa représentation base64 en mémoire brute (32
 * bytes). `b64_key`  : string base64 (telle que fournie par config.h) `key_out`
 * : buffer de 32 bytes fourni par le caller Retourne 1 si succès, 0 si échec
 * (clé invalide, mode "none", etc.)
 */
int crypto_init_key(const char *b64_key, unsigned char key_out[32]);

#endif /* KRATOS_CRYPTO_H */
