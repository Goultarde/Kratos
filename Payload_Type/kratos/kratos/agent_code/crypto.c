/*
 * crypto.c — AES-256-CBC + HMAC-SHA256
 *
 * Two backends selectable at compile time:
 *   -DUSE_BCRYPT   -> Windows BCrypt API (bcrypt.dll import)
 *   -DUSE_TINY_AES -> tiny-AES-c + homemade SHA-256 (zero crypto DLL import)
 *
 * Format Mythic : [IV 16B] [Ciphertext] [HMAC-SHA256 32B]
 * HMAC computed over (IV + Ciphertext). PKCS7 padding.
 */

#if defined(USE_TINY_AES)
/* ---- Backend tiny-AES: zero crypto DLL import ---------------------
 * Uses aes.c + sha256.c compiled into the binary.
 * IV generated via CryptGenRandom (advapi32 - already imported everywhere).
 * ──────────────────────────────────────────────────────────────────── */
/* AES256=1 CBC=1 ECB=0 CTR=0 injected via Makefile AES_DEFINES (all .c files) */
#include "aes.h"
#include "sha256.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#define AES_KEY_SIZE 32
#define AES_BLOCK_SIZE 16
#define HMAC_SIZE 32
#define IV_SIZE 16

/* RtlGenRandom loaded dynamically (SystemFunction036 in advapi32)
 * — ni wincrypt.h ni bcrypt.h requis, aucun import statique visible */
typedef BOOLEAN(WINAPI *RtlGenRandom_t)(PVOID, ULONG);

static int rand_bytes_tinyaes(unsigned char *buf, size_t len) {
  HMODULE hAdv = LoadLibraryA("advapi32.dll");
  if (!hAdv)
    return 0;
  RtlGenRandom_t fn = (RtlGenRandom_t)GetProcAddress(hAdv, "SystemFunction036");
  BOOLEAN ok = fn ? fn(buf, (ULONG)len) : FALSE;
  FreeLibrary(hAdv);
  return ok ? 1 : 0;
}

static int secure_memcmp_ta(const void *a, const void *b, size_t n) {
  const unsigned char *pa = (const unsigned char *)a;
  const unsigned char *pb = (const unsigned char *)b;
  unsigned char diff = 0;
  for (size_t i = 0; i < n; i++)
    diff |= pa[i] ^ pb[i];
  return diff;
}

unsigned char *aes256_encrypt(const unsigned char *aes_key,
                              const unsigned char *plaintext, size_t plain_len,
                              size_t *out_len) {
  /* PKCS7 padding */
  size_t pad = AES_BLOCK_SIZE - (plain_len % AES_BLOCK_SIZE);
  size_t padded = plain_len + pad;
  unsigned char *buf = (unsigned char *)malloc(padded);
  if (!buf)
    return NULL;
  memcpy(buf, plaintext, plain_len);
  memset(buf + plain_len, (unsigned char)pad, pad);

  /* Random IV */
  unsigned char iv[IV_SIZE];
  if (!rand_bytes_tinyaes(iv, IV_SIZE)) {
    free(buf);
    return NULL;
  }

  /* AES-256-CBC encrypt in-place */
  struct AES_ctx ctx;
  AES_init_ctx_iv(&ctx, aes_key, iv);
  AES_CBC_encrypt_buffer(&ctx, buf, padded);

  /* HMAC-SHA256(key, IV || ciphertext) */
  size_t iv_ciph_len = IV_SIZE + padded;
  unsigned char *iv_ciph = (unsigned char *)malloc(iv_ciph_len);
  if (!iv_ciph) {
    free(buf);
    return NULL;
  }
  memcpy(iv_ciph, iv, IV_SIZE);
  memcpy(iv_ciph + IV_SIZE, buf, padded);
  unsigned char mac[HMAC_SIZE];
  hmac_sha256(aes_key, AES_KEY_SIZE, iv_ciph, iv_ciph_len, mac);
  free(iv_ciph);

  /* Result: IV | ciphertext | HMAC */
  size_t total = IV_SIZE + padded + HMAC_SIZE;
  unsigned char *result = (unsigned char *)malloc(total);
  if (!result) {
    free(buf);
    return NULL;
  }
  memcpy(result, iv, IV_SIZE);
  memcpy(result + IV_SIZE, buf, padded);
  memcpy(result + IV_SIZE + padded, mac, HMAC_SIZE);
  free(buf);
  *out_len = total;
  return result;
}

unsigned char *aes256_decrypt(const unsigned char *aes_key,
                              const unsigned char *cipherblob, size_t blob_len,
                              size_t *out_len) {
  if (blob_len < IV_SIZE + AES_BLOCK_SIZE + HMAC_SIZE)
    return NULL;
  size_t cipher_len = blob_len - IV_SIZE - HMAC_SIZE;
  const unsigned char *iv = cipherblob;
  const unsigned char *cipher = cipherblob + IV_SIZE;
  const unsigned char *mac_in = cipherblob + IV_SIZE + cipher_len;

  /* Verify HMAC */
  size_t iv_ciph_len = IV_SIZE + cipher_len;
  unsigned char *iv_ciph = (unsigned char *)malloc(iv_ciph_len);
  if (!iv_ciph)
    return NULL;
  memcpy(iv_ciph, iv, IV_SIZE);
  memcpy(iv_ciph + IV_SIZE, cipher, cipher_len);
  unsigned char mac[HMAC_SIZE];
  hmac_sha256(aes_key, AES_KEY_SIZE, iv_ciph, iv_ciph_len, mac);
  free(iv_ciph);
  if (secure_memcmp_ta(mac, mac_in, HMAC_SIZE) != 0)
    return NULL;

  /* Decrypt */
  unsigned char *buf = (unsigned char *)malloc(cipher_len);
  if (!buf)
    return NULL;
  memcpy(buf, cipher, cipher_len);
  struct AES_ctx ctx;
  AES_init_ctx_iv(&ctx, aes_key, iv);
  AES_CBC_decrypt_buffer(&ctx, buf, cipher_len);

  /* Remove PKCS7 padding */
  if (cipher_len == 0) {
    free(buf);
    return NULL;
  }
  unsigned char pad = buf[cipher_len - 1];
  if (pad == 0 || pad > AES_BLOCK_SIZE) {
    free(buf);
    return NULL;
  }
  size_t plain_len = cipher_len - pad;
  buf[plain_len] = '\0';
  *out_len = plain_len;
  return buf;
}

int crypto_init_key(const char *b64_key, unsigned char key_out[32]) {
  if (!b64_key || strcmp(b64_key, "none") == 0)
    return 0;
  char *raw = base64_decode(b64_key, strlen(b64_key));
  if (!raw)
    return 0;
  memcpy(key_out, raw, 32);
  free(raw);
  return 1;
}

#elif defined(USE_BCRYPT)
/* ──── Backend BCrypt (Windows API) ───────────────────────────────────
 * crypto.h already includes windows.h + bcrypt.h in the correct order.
 * ──────────────────────────────────────────────────────────────────── */
#include "crypto.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ──────────────────────────────────────────────────────────────────
 * Constantes
 * ────────────────────────────────────────────────────────────────── */
#define AES_KEY_SIZE 32
#define AES_BLOCK_SIZE 16
#define HMAC_SIZE 32 /* SHA-256 */
#define IV_SIZE 16

/* ──────────────────────────────────────────────────────────────────
 * Helpers internes
 * ────────────────────────────────────────────────────────────────── */

/* Generates `len` cryptographically secure random bytes */
static int rand_bytes(unsigned char *buf, size_t len) {
  BCRYPT_ALG_HANDLE hAlg = NULL;
  NTSTATUS status =
      BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RNG_ALGORITHM, NULL, 0);
  if (!BCRYPT_SUCCESS(status))
    return 0;
  status = BCryptGenRandom(hAlg, buf, (ULONG)len, 0);
  BCryptCloseAlgorithmProvider(hAlg, 0);
  return BCRYPT_SUCCESS(status) ? 1 : 0;
}

/* ──────────────────────────────────────────────────────────────────
 * HMAC-SHA256
 * ────────────────────────────────────────────────────────────────── */

/*
 * Calcule HMAC-SHA256(key, data) → out[32]
 * Returns 1 on success, 0 on error.
 */
static int hmac_sha256(const unsigned char *key, size_t key_len,
                       const unsigned char *data, size_t data_len,
                       unsigned char out[HMAC_SIZE]) {
  BCRYPT_ALG_HANDLE hAlg = NULL;
  BCRYPT_HASH_HANDLE hHash = NULL;
  NTSTATUS status;
  int ret = 0;

  status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL,
                                       BCRYPT_ALG_HANDLE_HMAC_FLAG);
  if (!BCRYPT_SUCCESS(status))
    goto cleanup;

  status =
      BCryptCreateHash(hAlg, &hHash, NULL, 0, (PUCHAR)key, (ULONG)key_len, 0);
  if (!BCRYPT_SUCCESS(status))
    goto cleanup;

  status = BCryptHashData(hHash, (PUCHAR)data, (ULONG)data_len, 0);
  if (!BCRYPT_SUCCESS(status))
    goto cleanup;

  status = BCryptFinishHash(hHash, out, HMAC_SIZE, 0);
  if (!BCRYPT_SUCCESS(status))
    goto cleanup;

  ret = 1;

cleanup:
  if (hHash)
    BCryptDestroyHash(hHash);
  if (hAlg)
    BCryptCloseAlgorithmProvider(hAlg, 0);
  return ret;
}

/* Constant-time comparison to prevent timing attacks */
static int secure_memcmp(const unsigned char *a, const unsigned char *b,
                         size_t n) {
  unsigned char diff = 0;
  for (size_t i = 0; i < n; i++)
    diff |= a[i] ^ b[i];
  return diff == 0 ? 1 : 0;
}

/* ──────────────────────────────────────────────────────────────────
 * AES-256-CBC chiffrement
 * ────────────────────────────────────────────────────────────────── */

unsigned char *aes256_encrypt(const unsigned char *aes_key,
                              const unsigned char *plaintext, size_t plain_len,
                              size_t *out_len) {
  BCRYPT_ALG_HANDLE hAlg = NULL;
  BCRYPT_KEY_HANDLE hKey = NULL;
  NTSTATUS status;
  unsigned char *result = NULL;
  unsigned char *pbKeyObj = NULL;
  ULONG cbKeyObj = 0, cbData = 0;

  /* --- Padding PKCS7 --- */
  size_t pad_len = AES_BLOCK_SIZE - (plain_len % AES_BLOCK_SIZE);
  size_t padded_len = plain_len + pad_len;

  unsigned char *padded = (unsigned char *)malloc(padded_len);
  if (!padded)
    return NULL;
  memcpy(padded, plaintext, plain_len);
  memset(padded + plain_len, (unsigned char)pad_len, pad_len);

  /* --- Ouvrir provider AES --- */
  status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
  if (!BCRYPT_SUCCESS(status))
    goto cleanup;

  /* --- Mode CBC --- */
  status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                             (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
                             sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
  if (!BCRYPT_SUCCESS(status))
    goto cleanup;

  /* --- Key object size --- */
  status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&cbKeyObj,
                             sizeof(ULONG), &cbData, 0);
  if (!BCRYPT_SUCCESS(status))
    goto cleanup;

  pbKeyObj = (unsigned char *)malloc(cbKeyObj);
  if (!pbKeyObj)
    goto cleanup;

  /* --- Import the key --- */
  status = BCryptGenerateSymmetricKey(hAlg, &hKey, pbKeyObj, cbKeyObj,
                                      (PUCHAR)aes_key, AES_KEY_SIZE, 0);
  if (!BCRYPT_SUCCESS(status))
    goto cleanup;

  /* --- Generate random IV --- */
  unsigned char iv[IV_SIZE];
  if (!rand_bytes(iv, IV_SIZE))
    goto cleanup;

  /* --- Chiffrement CBC en place (BCrypt modifie l'IV donc on copie) --- */
  unsigned char iv_copy[IV_SIZE];
  memcpy(iv_copy, iv, IV_SIZE);

  /* Taille du ciphertext = padded_len */
  unsigned char *cipher = (unsigned char *)malloc(padded_len);
  if (!cipher)
    goto cleanup;

  ULONG cbCipher = 0;
  status = BCryptEncrypt(hKey, padded, (ULONG)padded_len, NULL, iv_copy,
                         IV_SIZE, cipher, (ULONG)padded_len, &cbCipher,
                         0); /* 0 = no BCrypt re-padding, already padded */
  if (!BCRYPT_SUCCESS(status)) {
    free(cipher);
    goto cleanup;
  }

  /* --- HMAC sur (IV + Ciphertext) --- */
  size_t iv_cipher_len = IV_SIZE + cbCipher;
  unsigned char *iv_cipher = (unsigned char *)malloc(iv_cipher_len);
  if (!iv_cipher) {
    free(cipher);
    goto cleanup;
  }
  memcpy(iv_cipher, iv, IV_SIZE);
  memcpy(iv_cipher + IV_SIZE, cipher, cbCipher);

  unsigned char hmac[HMAC_SIZE];
  if (!hmac_sha256(aes_key, AES_KEY_SIZE, iv_cipher, iv_cipher_len, hmac)) {
    free(iv_cipher);
    free(cipher);
    goto cleanup;
  }
  free(iv_cipher);

  /* --- Assemblage final : IV | Ciphertext | HMAC --- */
  *out_len = IV_SIZE + cbCipher + HMAC_SIZE;
  result = (unsigned char *)malloc(*out_len);
  if (!result) {
    free(cipher);
    goto cleanup;
  }

  memcpy(result, iv, IV_SIZE);
  memcpy(result + IV_SIZE, cipher, cbCipher);
  memcpy(result + IV_SIZE + cbCipher, hmac, HMAC_SIZE);
  free(cipher);

cleanup:
  if (hKey)
    BCryptDestroyKey(hKey);
  if (hAlg)
    BCryptCloseAlgorithmProvider(hAlg, 0);
  if (pbKeyObj)
    free(pbKeyObj);
  free(padded);
  return result;
}

/* ──────────────────────────────────────────────────────────────────
 * AES-256-CBC decryption
 * ────────────────────────────────────────────────────────────────── */

unsigned char *aes256_decrypt(const unsigned char *aes_key,
                              const unsigned char *cipherblob, size_t blob_len,
                              size_t *out_len) {
  /* Taille minimale : IV + 1 bloc + HMAC */
  if (blob_len < IV_SIZE + AES_BLOCK_SIZE + HMAC_SIZE)
    return NULL;

  const unsigned char *iv = cipherblob;
  size_t cipher_len = blob_len - IV_SIZE - HMAC_SIZE;
  const unsigned char *cipher = cipherblob + IV_SIZE;
  const unsigned char *hmac_recv = cipherblob + IV_SIZE + cipher_len;

  /* --- HMAC verification --- */
  unsigned char hmac_calc[HMAC_SIZE];
  if (!hmac_sha256(aes_key, AES_KEY_SIZE, cipherblob, IV_SIZE + cipher_len,
                   hmac_calc))
    return NULL;

  if (!secure_memcmp(hmac_calc, hmac_recv, HMAC_SIZE))
    return NULL; /* HMAC invalide → message tampered */

  /* --- AES-CBC decryption --- */
  BCRYPT_ALG_HANDLE hAlg = NULL;
  BCRYPT_KEY_HANDLE hKey = NULL;
  unsigned char *pbKeyObj = NULL;
  unsigned char *plain = NULL;
  ULONG cbKeyObj = 0, cbData = 0, cbPlain = 0;
  NTSTATUS status;

  status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
  if (!BCRYPT_SUCCESS(status))
    return NULL;

  status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                             (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
                             sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
  if (!BCRYPT_SUCCESS(status))
    goto dec_cleanup;

  status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&cbKeyObj,
                             sizeof(ULONG), &cbData, 0);
  if (!BCRYPT_SUCCESS(status))
    goto dec_cleanup;

  pbKeyObj = (unsigned char *)malloc(cbKeyObj);
  if (!pbKeyObj)
    goto dec_cleanup;

  status = BCryptGenerateSymmetricKey(hAlg, &hKey, pbKeyObj, cbKeyObj,
                                      (PUCHAR)aes_key, AES_KEY_SIZE, 0);
  if (!BCRYPT_SUCCESS(status))
    goto dec_cleanup;

  plain = (unsigned char *)malloc(cipher_len + 1);
  if (!plain)
    goto dec_cleanup;

  /* BCrypt modifie l'IV → on copie */
  unsigned char iv_copy[IV_SIZE];
  memcpy(iv_copy, iv, IV_SIZE);

  status = BCryptDecrypt(hKey, (PUCHAR)cipher, (ULONG)cipher_len, NULL, iv_copy,
                         IV_SIZE, plain, (ULONG)cipher_len, &cbPlain, 0);
  if (!BCRYPT_SUCCESS(status)) {
    free(plain);
    plain = NULL;
    goto dec_cleanup;
  }

  /* --- Supprimer le padding PKCS7 --- */
  if (cbPlain == 0 || plain[cbPlain - 1] > AES_BLOCK_SIZE ||
      plain[cbPlain - 1] == 0) {
    free(plain);
    plain = NULL;
    goto dec_cleanup;
  }
  ULONG pad = plain[cbPlain - 1];

  /* Verify all padding bytes are correct */
  for (ULONG i = 0; i < pad; i++) {
    if (plain[cbPlain - 1 - i] != (unsigned char)pad) {
      free(plain);
      plain = NULL;
      goto dec_cleanup;
    }
  }

  *out_len = cbPlain - pad;
  plain[*out_len] = '\0';

dec_cleanup:
  if (hKey)
    BCryptDestroyKey(hKey);
  if (hAlg)
    BCryptCloseAlgorithmProvider(hAlg, 0);
  if (pbKeyObj)
    free(pbKeyObj);
  return plain;
}

/* ──────────────────────────────────────────────────────────────────
 * Key initialization from base64
 * ────────────────────────────────────────────────────────────────── */

int crypto_init_key(const char *b64_key, unsigned char key_out[32]) {
  if (!b64_key || strlen(b64_key) == 0)
    return 0;

  /* Mode plaintext explicite */
  if (strcmp(b64_key, "none") == 0 ||
      strcmp(b64_key, "aes256_hmac") == 0) /* unresolved stub -> no key */
    return 0;

  size_t key_len = 0;
  unsigned char *key_bytes =
      base64_decode_bin(b64_key, strlen(b64_key), &key_len);
  if (!key_bytes)
    return 0;

  if (key_len != AES_KEY_SIZE) {
    free(key_bytes);
    return 0;
  }

  memcpy(key_out, key_bytes, AES_KEY_SIZE);
  free(key_bytes);
  return 1;
}

#else
// Default if not specified at compile time (mostly for linter)
#ifndef USE_TINY_AES
#define USE_TINY_AES
#endif
#endif /* USE_BCRYPT / USE_TINY_AES */
