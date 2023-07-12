/*
 * Copyright (C) 2011-2019 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


// Enclave.cpp : Defines the exported functions for the .so application
#include "sgx_eid.h"
#include "sgx_trts.h"
#include "sgx_tseal.h"
#include "sgx_tae_service.h"
#include "Enclave_t.h"
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include "sgx_dh.h"
#include <map>

#include "tSgxSSL_api.h"
#include "Enclave.h"
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/hmac.h>
#include <openssl/obj_mac.h>

#define UNUSED(val) (void)(val)
typedef struct 
{
    sgx_mc_uuid_t mc;
    uint32_t mc_value;
    uint8_t secret[32];
    uint8_t data[1024];
}sealed_payload;
  

void inner_calc_prf(uint8_t*, uint32_t*, uint8_t*, uint32_t, uint8_t*, uint32_t);

std::map<uint64_t, eke_sa_t>g_sa_info_map;

int printf(const char* fmt, ...)
{
    char buf[BUFSIZ] = { '\0' };
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print(buf);
    return (int)strnlen(buf, BUFSIZ - 1) + 1;
}

void generate_random_number(uint8_t* rand, uint32_t rlen)
{
    ocall_print("Ecall to generate a nonce...");
    RAND_bytes((uint8_t*)rand, rlen); 
}

void init_session(uint64_t spi)
{
    eke_sa_t eke_sa_info;

    memset(&eke_sa_info, 0, sizeof(eke_sa_t));
    g_sa_info_map.insert(std::pair<uint64_t, eke_sa_t>(spi, eke_sa_info));

    printf("session for spi: %llu\n", spi);
}

void seal_crypto_context(
    uint8_t is_initiator,
    uint64_t spi,
    uint8_t* sealed_data,
    uint32_t* sealed_size
)
{
    uint32_t ret = 0;
    int busy_retry_times = 2;
    sealed_payload data2seal;
    uint32_t size = 0;

    std::map<uint64_t, eke_sa_t>::iterator it = g_sa_info_map.find(spi);

    if(it != g_sa_info_map.end()){
        size = sgx_calc_sealed_data_size(0, sizeof(sealed_payload));

        do{
            ret = sgx_create_pse_session();
        }while(ret == SGX_ERROR_BUSY && busy_retry_times--);
        if(ret != SGX_SUCCESS) return;

        ret = sgx_create_monotonic_counter(&data2seal.mc, &data2seal.mc_value);
        if(ret != SGX_SUCCESS)
            ocall_print("sgx_create_monotonic_counter() failed");

        ret = sgx_read_rand(data2seal.secret, 32);
        if(ret != SGX_SUCCESS)
            ocall_print("sgx_read_rand() failed");

        /* forming data for sealing */
        memcpy(data2seal.data, (it->second).dh_private_key, (it->second).dh_pklen);
        memcpy(data2seal.data+(it->second).dh_pklen, (it->second).skeyseed, (it->second).seed_len);
        memcpy(data2seal.data+(it->second).seed_len, (it->second).psk, (it->second).psk_len);
        memcpy(data2seal.data+(it->second).psk_len, (it->second).sk_d, (it->second).dkey_len);
        memcpy(data2seal.data+(it->second).dkey_len, (it->second).sk_pi, (it->second).pkey_len);
        memcpy(data2seal.data+(it->second).pkey_len, (it->second).sk_pr, (it->second).pkey_len);
        if(!is_initiator)
            memcpy(data2seal.data+(it->second).pkey_len, (it->second).dh_shared_key, (it->second).dh_sklen);
        
        /* free & nullifying data for sealing */   
        free((it->second).dh_private_key);
	(it->second).dh_private_key = NULL;

        free((it->second).skeyseed);
	(it->second).skeyseed = NULL;

        free((it->second).psk);
        (it->second).psk = NULL;
   
        free((it->second).sk_d);
        (it->second).sk_d = NULL;

        free((it->second).sk_pi);
        (it->second).sk_pi = NULL;

        free((it->second).sk_pr);
        (it->second).sk_pr = NULL;

	if(!is_initiator){
	    free((it->second).dh_shared_key);
	    (it->second).dh_shared_key = NULL;
	}

        /* do seal */
        ret = sgx_seal_data(0, NULL, sizeof(data2seal), (uint8_t*)&data2seal, size, (sgx_sealed_data_t*)sealed_data);
        if(ret != SGX_SUCCESS){ 
            *sealed_size = 0;
            ocall_print("sgx_seal_data() failed");
        }else{
            *sealed_size = sizeof(data2seal);
        }
        memset_s(&data2seal, sizeof(sealed_payload), 0, sizeof(sealed_payload));
        sgx_close_pse_session();
    }
}

void generate_dh(
    uint8_t is_initiator,
    uint64_t spi,
    uint32_t klen,
    uint8_t* i_dh_data, uint32_t iklen,
    uint8_t* r_dh_data, 
    const char *dh_p, 
    const char *dh_g
#if 1 /* DEBUG */
        ,
    uint8_t* data
#endif
)
{
    /* setup DH */
    DH *dh = DH_new();
    BIGNUM *p = NULL;
    BIGNUM *g = NULL;
    const BIGNUM *pub_key, *priv_key;
    BN_hex2bn(&p, dh_p);
    BN_hex2bn(&g, dh_g);
    DH_set0_pqg(dh, p, NULL, g);
    
    /* generate a keypair */
    DH_generate_key(dh);

    /* find an eke_sa_t from map */
    std::map<uint64_t, eke_sa_t>::iterator it = g_sa_info_map.find(spi);

    if(it != g_sa_info_map.end()){
        /* initiator */
	if(is_initiator)
          {
            (it->second).dh_private_key = (uint8_t*)malloc(klen);
            DH_get0_key(dh, &pub_key, &priv_key);
            BN_bn2bin(pub_key, i_dh_data);
            BN_bn2bin(priv_key, (it->second).dh_private_key);
            (it->second).dh_pklen = klen;
 
            BN_bn2bin(priv_key, data); /* DEBUG */
          }
        else /* responder */
          {
            DH_get0_key(dh, &pub_key, &priv_key);
            BN_bn2bin(pub_key, r_dh_data);
         
            BIGNUM *ex = NULL;
            ex = BN_bin2bn(i_dh_data, iklen, NULL);
            (it->second).dh_shared_key = (uint8_t*)malloc(klen);
            DH_compute_key((it->second).dh_shared_key, ex, dh);
            (it->second).dh_sklen = klen;

            DH_compute_key(data, ex, dh); /* DEBUG */
            BN_clear_free(ex);
          }
    }else
        printf("Cannot find a map for spi=%llu", spi);
}

void complete_dh(
    uint64_t spi,
    uint32_t klen,
    uint8_t* r_dh_data, uint32_t rklen, 
    const char *dh_p, 
    const char *dh_g
#if 1 /* DEBUG */
        ,
    uint8_t* data
#endif
)
{
    /* setup DH */
    DH *dh = DH_new();
    BIGNUM *p = NULL;
    BIGNUM *g = NULL;
    BIGNUM *priv_key;

    BN_hex2bn(&p, dh_p);
    BN_hex2bn(&g, dh_g);
    DH_set0_pqg(dh, p, NULL, g);
    
    /* find an eke_sa_t from map */
    std::map<uint64_t, eke_sa_t>::iterator it = g_sa_info_map.find(spi);

    if(it != g_sa_info_map.end()){
	priv_key = BN_bin2bn(
            (it->second).dh_private_key, (it->second).dh_pklen, NULL);
        DH_set0_key(dh, NULL, priv_key);

        BIGNUM *ex = NULL;
        ex = BN_bin2bn(r_dh_data, rklen, NULL);
        (it->second).dh_shared_key = (uint8_t*)malloc(klen);
        DH_compute_key((it->second).dh_shared_key, ex, dh);
        (it->second).dh_sklen = klen;

        DH_compute_key(data, ex, dh); /* DEBUG */
        BN_clear_free(ex);
    }else
        printf("Cannot find a map for spi=%llu", spi);
}

void inner_calc_prf(
    uint8_t mode,
    uint8_t* out, uint32_t *olen, 
    uint8_t* key, uint32_t klen, 
    uint8_t* data, uint32_t dlen
)
{
    HMAC_CTX *ctx = NULL;
    const EVP_MD* md;
    unsigned int len = 0;

    /* create MD context */
    switch(mode){
    case SKE_TRANSFORM_PRF_TYPE_PRF_HMAC_SHA1: md = EVP_sha1(); break;
    case SKE_TRANSFORM_PRF_TYPE_PRF_HMAC_SHA2_256: md = EVP_sha256(); break;
    case SKE_TRANSFORM_PRF_TYPE_PRF_HMAC_SHA2_384: md = EVP_sha384(); break;
    case SKE_TRANSFORM_PRF_TYPE_PRF_HMAC_SHA2_512: md = EVP_sha512(); break;
    default: md = NULL; break;
    }

    ctx = HMAC_CTX_new();
    HMAC_Init_ex(ctx, key, klen, md, NULL);
    HMAC_Update(ctx, data, dlen);
    HMAC_Final(ctx, out, &len);

    *olen = len;

    HMAC_CTX_free(ctx);
}

void calc_prf(
    uint64_t spi, 
    uint8_t type,
    uint8_t mode,
    uint8_t is_initiator,
    uint16_t tr, 
    uint8_t* data, uint32_t dlen,
    uint8_t* out, uint32_t* olen 
)
{
    /* find an eke_sa_t from map */
    std::map<uint64_t, eke_sa_t>::iterator it = g_sa_info_map.find(spi);

    if(it != g_sa_info_map.end()){
        if(type == TYPE_SKEYSEED){
            (it->second).skeyseed = (uint8_t*)malloc(tr);

            inner_calc_prf(mode,
                       (it->second).skeyseed, &((it->second).seed_len), 
                        data, dlen,  
                        (it->second).dh_shared_key, (it->second).dh_sklen);
#if 1 /* DEBUG */
            memcpy(out, (it->second).skeyseed, (it->second).seed_len);
            *olen = (it->second).seed_len;
#endif
         }

        if(type == TYPE_AUTHMSG){
           inner_calc_prf(mode, out, olen, 
                      (is_initiator ? (it->second).sk_pr : (it->second).sk_pi),
                      (it->second).pkey_len,
                      data, dlen);
        }

        if(type == TYPE_AUTH1){
           uint8_t *key_pad;
           uint8_t *auth_data;
           uint32_t key_pad_len = 0;
           uint32_t auth_data_len = 0;

           /* setup for calculation */
	   (it->second).psk = (uint8_t*)malloc(tr);
           key_pad_len = strlen(EKE_KEY_PAD);
           auth_data_len = strlen(AUTH_DATA); 
           key_pad = (uint8_t*)malloc(key_pad_len);
           auth_data = (uint8_t*)malloc(auth_data_len);

           memcpy(key_pad, EKE_KEY_PAD, key_pad_len);
           memcpy(auth_data, AUTH_DATA, auth_data_len);
           
           /* PSK */
           inner_calc_prf(mode, (it->second).psk, &((it->second).psk_len),
                          auth_data, auth_data_len, 
                          key_pad, key_pad_len);

           /* AUTH */
           inner_calc_prf(mode, out, olen, 
                          (it->second).psk, (it->second).psk_len,
                          data, dlen);
        }

        if(type == TYPE_AUTH2){
           inner_calc_prf(mode, out, olen,
                          (it->second).psk, (it->second).psk_len,
                           data, dlen);
        }  
    }else
         printf("Failed in calc_prf(): session %d cannot be found\n", spi);
}

void calc_prfplus(
    uint64_t spi,
    uint8_t is_parent,
    uint8_t mode,
    uint8_t* data, uint32_t dlen,
    uint32_t dkey_len,
    uint32_t ikey_len,
    uint32_t ekey_len,
    uint32_t pkey_len   
#if 1 /* DEBUG */
    , 
    uint8_t* keymat
#endif
)
{
    unsigned int keymat_len = (is_parent ? dkey_len : 0) + 2*ikey_len + 2*ekey_len + 2*pkey_len;
    uint8_t *t = 0, *s = 0, *ret = 0;
    uint8_t *p = 0, *q = 0; /* pointers for operation */
    uint8_t x = 0;
    unsigned int ret_len = 0;
    unsigned int slen = 0;
    unsigned int tlen = 0;
    unsigned int tr = dkey_len;


    /* find an eke_sa_t from map */
    std::map<uint64_t, eke_sa_t>::iterator it = g_sa_info_map.find(spi);

    if(it != g_sa_info_map.end()){
        /* prf+ (K,S) = T1 | T2 | T3 | T4 | ...
 
           where:
           T1 = prf(K, S | 0x01)
           T2 = prf(K, T1 | S | 0x02)
           T1 = prf(K, T2 | S | 0x03)
           T1 = prf(K, T3 | S | 0x04)
         */
        /* allocate memory for keymat */
        ret = (uint8_t*)malloc(keymat_len);
        q = ret;

        while (ret_len < keymat_len && x < 255)
        {
            /* calculate slen */
            if(t){
                slen = tlen + dlen + 1;
            }else{
                slen = dlen + 1;
            }

            /* alloc memory for s */
            s = (uint8_t*)malloc(slen);
            p = s;

            /* form s for prf */
            if(t) {
                memcpy(p, t, tlen); 
                p += tlen;
                t = NULL;
                tlen = 0;
            }
            memcpy(p, data, dlen);
            p += dlen;
            *p = (unsigned char)(x+1);
     
            /* calculate t for prf */ 
            t = (uint8_t*)malloc(tr);
            inner_calc_prf(mode, t, &tlen, 
                    (is_parent ? (it->second).skeyseed : (it->second).sk_d), 
                    (is_parent ? (it->second).seed_len : (it->second).dkey_len), 
                    s, slen);

            /* append the calculated t */
            memcpy(q, t, tlen);
            q += tlen;
            ret_len += tlen;

            s = NULL;
            slen = 0;
            x++;
        }

        if( x == 255) ret = NULL;

#if 1 /* DEBUG */
        if(ret != NULL) memcpy(keymat, ret, keymat_len);
#endif
     
        /* assign each key */
        if(is_parent == IS_PARENT){
            int pos = 0;

            /* allocate memory for each key */
            (it->second).sk_d = (uint8_t*)malloc(dkey_len);
            (it->second).sk_ai = (uint8_t*)malloc(ikey_len);
            (it->second).sk_ar = (uint8_t*)malloc(ikey_len);
            (it->second).sk_ei = (uint8_t*)malloc(ekey_len);
            (it->second).sk_er = (uint8_t*)malloc(ekey_len);
            (it->second).sk_pi = (uint8_t*)malloc(pkey_len);
            (it->second).sk_pr = (uint8_t*)malloc(pkey_len);

            /* assign each key to the allocated memory */
            /* SK_d */
            memcpy((it->second).sk_d, ret + pos, dkey_len);
            pos += dkey_len;

            /* SK_ai */
            memcpy((it->second).sk_ai, ret + pos, ikey_len);
            pos += ikey_len;

            /* SK_ar */
            memcpy((it->second).sk_ar, ret + pos, ikey_len);
            pos += ikey_len;

            /* SK_ei */
            memcpy((it->second).sk_ei, ret + pos, ekey_len);
            pos += ekey_len;

            /* SK_er */
            memcpy((it->second).sk_er, ret + pos, ekey_len);
            pos += ekey_len;

            /* SK_pi */
            memcpy((it->second).sk_pi, ret + pos, pkey_len);
            pos += pkey_len;

            /* SK_pr */
            memcpy((it->second).sk_pr, ret + pos, pkey_len);
            pos += pkey_len;

            /* assign each key length */
            (it->second).dkey_len = dkey_len;
            (it->second).ikey_len = ikey_len;
            (it->second).ekey_len = ekey_len;
            (it->second).pkey_len = pkey_len;
        }else if (is_parent == IS_CHILD){
            int pos = 0;

            /* allocate memory for child sa */
            (it->second).childs = (eke_child_sa_t*)malloc(sizeof(eke_child_sa_t));

            /* allocate memory for each key */
            (it->second).childs[0].sk_ai = (uint8_t*)malloc(ikey_len);
            (it->second).childs[0].sk_ar = (uint8_t*)malloc(ikey_len);
            (it->second).childs[0].sk_ei = (uint8_t*)malloc(ekey_len);
            (it->second).childs[0].sk_er = (uint8_t*)malloc(ekey_len);

            /* assign each key to the allocated memory */
            /* SK_ei */
            memcpy((it->second).childs[0].sk_ei, ret + pos, ekey_len);
            pos += ekey_len;

            /* SK_ai */
            memcpy((it->second).childs[0].sk_ai, ret + pos, ikey_len);
            pos += ikey_len;

            /* SK_er */
            memcpy((it->second).childs[0].sk_er, ret + pos, ekey_len);
            pos += ekey_len;

            /* SK_ar */
            memcpy((it->second).childs[0].sk_ar, ret + pos, ikey_len);
            pos += ikey_len;

            /* assign each key length */
            (it->second).childs[0].ikey_len = ikey_len;
            (it->second).childs[0].ekey_len = ekey_len;
        }
    }else
        ocall_print("Failed in calc_prfplus()");
}

void calc_integr(
    uint64_t spi,
    uint8_t is_initiator,
    uint8_t mode,
    uint8_t *data,
    uint32_t dlen,
    uint8_t *out,
    uint32_t *olen
)
{
    HMAC_CTX *hctx = NULL;
    const EVP_MD* md; 

    /* create md context */
    switch(mode){
    case SKE_TRANSFORM_INTEG_TYPE_AUTH_HMAC_SHA1_96:
    case SKE_TRANSFORM_INTEG_TYPE_AUTH_HMAC_SHA1_160:
        md = EVP_sha1(); break;
    case SKE_TRANSFORM_INTEG_TYPE_AUTH_HMAC_SHA2_256_128: md = EVP_sha256(); break;
    case SKE_TRANSFORM_INTEG_TYPE_AUTH_HMAC_SHA2_384_192: md = EVP_sha384(); break;
    case SKE_TRANSFORM_INTEG_TYPE_AUTH_HMAC_SHA2_512_256: md = EVP_sha512(); break;
    default: md = NULL; break;
    }

    /* find an eke_sa_t from map */
    std::map<uint64_t, eke_sa_t>::iterator it = g_sa_info_map.find(spi);

    if(it != g_sa_info_map.end()){
        hctx = HMAC_CTX_new();
        HMAC_Init_ex(hctx,
            (is_initiator ?  (it->second).sk_ar : (it->second).sk_ai), (it->second).ikey_len, md, NULL);
        HMAC_Update(hctx, (const uint8_t*) data, dlen);
        HMAC_Final(hctx, out, olen);
    }else
        ocall_print("Failed in calc_integr()");

    HMAC_CTX_free(hctx);
}

void decrypt_data(
    uint64_t spi,
    uint8_t is_initiator,
    uint8_t mode,
    uint8_t block_size,
    uint8_t *data,
    uint32_t dlen,
    uint8_t *out,
    uint32_t *olen
)
{
    EVP_CIPHER_CTX *ctx = NULL;
    const EVP_CIPHER *cipher;
    int out_len = 0;

    /* create cipher context */
    switch(mode){
    case SKE_TRANSFORM_ENCR_TYPE_AES_CBC_128: cipher = EVP_aes_128_cbc(); break;
    case SKE_TRANSFORM_ENCR_TYPE_AES_CBC_192: cipher = EVP_aes_192_cbc(); break;
    case SKE_TRANSFORM_ENCR_TYPE_AES_CBC_256: cipher = EVP_aes_256_cbc(); break;
    default: cipher = NULL; break;
    }

    /* find an eke_sa_t from map */
    std::map<uint64_t, eke_sa_t>::iterator it = g_sa_info_map.find(spi);

    if(it != g_sa_info_map.end()){
        ctx = EVP_CIPHER_CTX_new();

        EVP_DecryptInit_ex(ctx, cipher, NULL, 
            (is_initiator ?  (it->second).sk_er : (it->second).sk_ei), data);
        EVP_DecryptUpdate(ctx, out, &out_len, data + block_size, dlen - block_size);
        EVP_DecryptFinal_ex(ctx, out + out_len, &out_len);
        *olen = out_len;
    }else
        ocall_print("Failed in decrypt_data()");

    EVP_CIPHER_CTX_free(ctx);
}

void encrypt_data(
    uint64_t spi,
    uint8_t is_initiator,
    uint8_t mode,
    uint8_t block_size,
    uint8_t *data,
    uint32_t dlen,
    uint8_t *out,
    uint32_t *olen
)
{
    EVP_CIPHER_CTX *ctx = NULL;
    const EVP_CIPHER *cipher;
    int out_len = 0;

    /* create cipher context */
    switch(mode){
    case SKE_TRANSFORM_ENCR_TYPE_AES_CBC_128: cipher = EVP_aes_128_cbc(); break;
    case SKE_TRANSFORM_ENCR_TYPE_AES_CBC_192: cipher = EVP_aes_192_cbc(); break;
    case SKE_TRANSFORM_ENCR_TYPE_AES_CBC_256: cipher = EVP_aes_256_cbc(); break;
    default: cipher = NULL; break;
    }

    /* find an eke_sa_t from map */
    std::map<uint64_t, eke_sa_t>::iterator it = g_sa_info_map.find(spi);

    if(it != g_sa_info_map.end()){
        ctx = EVP_CIPHER_CTX_new();

        EVP_EncryptInit_ex(ctx, cipher, NULL, 
            (is_initiator ?  (it->second).sk_ei : (it->second).sk_er), out);
        EVP_EncryptUpdate(ctx, out + block_size, &out_len, data, dlen);
        *olen = out_len;
    }else
        ocall_print("Failed in encrypt_data()");

    EVP_CIPHER_CTX_free(ctx);
}
   

