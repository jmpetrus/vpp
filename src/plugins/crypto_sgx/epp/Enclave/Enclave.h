#ifndef _ENCLAVE_H_
#define _ENCLAVE_H_

#include <assert.h>
#include <stdlib.h>

#include <openssl/evp.h>

#if defined(__cplusplus)
extern "C" {
#endif

/* encryption function */
#define EPP_TRANSFORM_ENCR_TYPE_DES_CBC 1
#define EPP_TRANSFORM_ENCR_TYPE_3DES_CBC 2
#define EPP_TRANSFORM_ENCR_TYPE_AES_CBC_128 3
#define EPP_TRANSFORM_ENCR_TYPE_AES_CBC_192 4
#define EPP_TRANSFORM_ENCR_TYPE_AES_CBC_256 5
#define EPP_TRANSFORM_ENCR_TYPE_AES_CTR_128 6 
#define EPP_TRANSFORM_ENCR_TYPE_AES_CTR_192 7
#define EPP_TRANSFORM_ENCR_TYPE_AES_CTR_256 8
#define EPP_TRANSFORM_ENCR_TYPE_AES_GCM_128 9
#define EPP_TRANSFORM_ENCR_TYPE_AES_GCM_192 10
#define EPP_TRANSFORM_ENCR_TYPE_AES_GCM_256 11

/* hmac function */
#define EPP_TRANSFORM_HMAC_TYPE_MD5 12
#define EPP_TRANSFORM_HMAC_TYPE_SHA1 13
#define EPP_TRANSFORM_HMAC_TYPE_SHA224 14
#define EPP_TRANSFORM_HMAC_TYPE_SHA256 15
#define EPP_TRANSFORM_HMAC_TYPE_SHA384 16
#define EPP_TRANSFORM_HMAC_TYPE_SHA512 17

typedef struct
{
  EVP_CIPHER_CTX *ctx;
  const EVP_CIPHER *cipher; 
}epp_cipher_t;

typedef struct
{
  HMAC_CTX *ctx;
  const EVP_MD *hmac; 
}epp_hmac_t;

typedef struct
{
  EVP_CIPHER_CTX *ctx;
  const EVP_CIPHER *cipher;
  HMAC_CTX *hctx;
  const EVP_MD *hmac;
}epp_aed_t;

#if defined(__cplusplus)
}
#endif

#endif /* !_ENCLAVE_H_ */
