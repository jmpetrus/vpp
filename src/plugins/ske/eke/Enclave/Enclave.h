#ifndef _ENCLAVE_H_
#define _ENCLAVE_H_

#include <assert.h>
#include <stdlib.h>

#include <openssl/evp.h>

#if defined(__cplusplus)
extern "C" {
#endif

#define TYPE_SKEYSEED	1
#define TYPE_KEYMAT	2
#define TYPE_AUTHMSG	3
#define TYPE_AUTH1	4
#define TYPE_AUTH2	5

#define IS_PARENT 1
#define IS_CHILD 0

#define SKE_TRANSFORM_ENCR_TYPE_AES_CBC_128 1
#define SKE_TRANSFORM_ENCR_TYPE_AES_CBC_192 2
#define SKE_TRANSFORM_ENCR_TYPE_AES_CBC_256 3

#define SKE_TRANSFORM_PRF_TYPE_PRF_HMAC_SHA1 1
#define SKE_TRANSFORM_PRF_TYPE_PRF_HMAC_SHA2_256 2
#define SKE_TRANSFORM_PRF_TYPE_PRF_HMAC_SHA2_384 3
#define SKE_TRANSFORM_PRF_TYPE_PRF_HMAC_SHA2_512 4

#define SKE_TRANSFORM_INTEG_TYPE_AUTH_HMAC_SHA1_96 1
#define SKE_TRANSFORM_INTEG_TYPE_AUTH_HMAC_SHA1_160 2
#define SKE_TRANSFORM_INTEG_TYPE_AUTH_HMAC_SHA2_256_128 3
#define SKE_TRANSFORM_INTEG_TYPE_AUTH_HMAC_SHA2_384_192 4
#define SKE_TRANSFORM_INTEG_TYPE_AUTH_HMAC_SHA2_512_256 5

#define AUTH_DATA "Vpp123"
#define EKE_KEY_PAD "Key Pad for IKEv2"

typedef struct
{
  uint8_t *data;
  uint8_t hex;
  EVP_PKEY *key;
}eke_auth_t;

typedef struct
{
  /* keys */
  uint8_t *sk_ai;
  uint8_t *sk_ar;
  uint32_t ikey_len;
  uint8_t *sk_ei;
  uint8_t *sk_er;
  uint32_t ekey_len;
}eke_child_sa_t;

typedef struct
{
  /* DH */
  uint8_t *dh_shared_key;
  uint8_t *dh_private_key;
  uint32_t dh_sklen;
  uint32_t dh_pklen;

  /* SKEYSEED */
  uint8_t *skeyseed;
  uint32_t seed_len;

  /* PSK */
  uint8_t *psk;
  uint32_t psk_len;

  /* keys */
  uint8_t *sk_d;
  uint32_t dkey_len;
  uint8_t *sk_ai;
  uint8_t *sk_ar;
  uint32_t ikey_len;
  uint8_t *sk_ei;
  uint8_t *sk_er;
  uint32_t ekey_len;
  uint8_t *sk_pi;
  uint8_t *sk_pr;
  uint32_t pkey_len;

  /* auth */
  eke_auth_t i_auth;
  eke_auth_t r_auth;

  /* child sas */
  eke_child_sa_t *childs;
}eke_sa_t;

#if defined(__cplusplus)
}
#endif

#endif /* !_ENCLAVE_H_ */
