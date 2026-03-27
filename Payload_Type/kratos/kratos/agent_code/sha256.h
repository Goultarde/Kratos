/*
 * sha256.h — SHA-256 + HMAC-SHA256 (domaine public, zéro dépendance)
 */
#ifndef KRATOS_SHA256_H
#define KRATOS_SHA256_H

#include <stddef.h>
#include <stdint.h>

void sha256(const uint8_t *data, size_t len, uint8_t digest[32]);
void hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data,
                 size_t data_len, uint8_t mac[32]);

#endif /* KRATOS_SHA256_H */
