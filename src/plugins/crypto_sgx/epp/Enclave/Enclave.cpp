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

#define ENABLE_FORWARDING 1

#define UNUSED(val) (void)(val)

std::map<uint32_t, epp_cipher_t>g_cipher_map;
std::map<uint32_t, epp_hmac_t>g_hmac_map;
std::map<uint32_t, epp_aed_t>g_aed_map;

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

/* initialize context for encryption/decryption */
void cipher_init(uint32_t spi, uint8_t is_encrypt, uint32_t alg, uint8_t* keydata)
{
    epp_cipher_t epp_cipher_info;
    int ret = 0;

    printf("%s: spi=%x, is_encrypt=%d, alg=%d\n", __FUNCTION__, spi, is_encrypt, alg);

    /* initialize context */
    epp_cipher_info.ctx = EVP_CIPHER_CTX_new();
    switch(alg){
    case EPP_TRANSFORM_ENCR_TYPE_DES_CBC: epp_cipher_info.cipher = EVP_des_cbc(); break;
    case EPP_TRANSFORM_ENCR_TYPE_3DES_CBC: epp_cipher_info.cipher = EVP_des_ede3_cbc(); break;
    case EPP_TRANSFORM_ENCR_TYPE_AES_CBC_128: epp_cipher_info.cipher = EVP_aes_128_cbc(); break;
    case EPP_TRANSFORM_ENCR_TYPE_AES_CBC_192: epp_cipher_info.cipher = EVP_aes_192_cbc(); break;
    case EPP_TRANSFORM_ENCR_TYPE_AES_CBC_256: epp_cipher_info.cipher = EVP_aes_256_cbc(); break;
    case EPP_TRANSFORM_ENCR_TYPE_AES_GCM_128: epp_cipher_info.cipher = EVP_aes_128_gcm(); break;
    case EPP_TRANSFORM_ENCR_TYPE_AES_GCM_192: epp_cipher_info.cipher = EVP_aes_192_gcm(); break;
    case EPP_TRANSFORM_ENCR_TYPE_AES_GCM_256: epp_cipher_info.cipher = EVP_aes_256_gcm(); break;
    case EPP_TRANSFORM_ENCR_TYPE_AES_CTR_128: epp_cipher_info.cipher = EVP_aes_128_ctr(); break;
    case EPP_TRANSFORM_ENCR_TYPE_AES_CTR_192: epp_cipher_info.cipher = EVP_aes_192_ctr(); break;
    case EPP_TRANSFORM_ENCR_TYPE_AES_CTR_256: epp_cipher_info.cipher = EVP_aes_256_ctr(); break;
    }

    /* initialize en/decryption */
    if(is_encrypt) 
        ret = EVP_EncryptInit_ex(epp_cipher_info.ctx,  epp_cipher_info.cipher, NULL, keydata, NULL);
    else
        ret = EVP_DecryptInit_ex(epp_cipher_info.ctx,  epp_cipher_info.cipher, NULL, keydata, NULL);

    if(ret != 1) printf("Failed in EVP_En/DecryptInit_ex(ret=%x)", ret);

    /* disable padding */
    EVP_CIPHER_CTX_set_padding(epp_cipher_info.ctx, 0);

    /* insert the contexted into map */
    g_cipher_map.insert(std::pair<uint32_t, epp_cipher_t>(spi, epp_cipher_info));
}

/* initialize hmac context */
void hmac_init(uint32_t spi, uint32_t alg, uint8_t* keydata, uint32_t keylen)
{
    epp_hmac_t epp_hmac_info;
    int ret = 0;

    printf("%s: spi=%x, alg=%d\n", __FUNCTION__, spi, alg);
    /* initialize context */
    epp_hmac_info.ctx = HMAC_CTX_new();
    switch(alg){
    case EPP_TRANSFORM_HMAC_TYPE_MD5: epp_hmac_info.hmac = EVP_md5(); break;
    case EPP_TRANSFORM_HMAC_TYPE_SHA1: epp_hmac_info.hmac = EVP_sha1(); break;
    case EPP_TRANSFORM_HMAC_TYPE_SHA224: epp_hmac_info.hmac = EVP_sha224(); break;
    case EPP_TRANSFORM_HMAC_TYPE_SHA256: epp_hmac_info.hmac = EVP_sha256(); break;
    case EPP_TRANSFORM_HMAC_TYPE_SHA384: epp_hmac_info.hmac = EVP_sha384(); break;
    case EPP_TRANSFORM_HMAC_TYPE_SHA512: epp_hmac_info.hmac = EVP_sha512(); break;
    }

    /* initialize hmac context */
    ret = HMAC_Init_ex(epp_hmac_info.ctx, keydata, keylen, epp_hmac_info.hmac, NULL);
    if(ret != 1) printf("Failed in HMAC_Init_ex(ret=%x)", ret);

    /* insert the context into map */
    g_hmac_map.insert(std::pair<uint32_t, epp_hmac_t>(spi, epp_hmac_info));
}

/* initialize context for AD-merging */
void aed_init(uint32_t spi, uint8_t is_encrypt, uint32_t enc_alg, uint32_t int_alg, uint8_t* keydata, uint8_t* int_keydata, uint32_t int_keylen)
{
    epp_aed_t epp_aed_info;
    int ret = 0;

    /* initialize context */
    epp_aed_info.ctx = EVP_CIPHER_CTX_new();
    switch(enc_alg){
    case EPP_TRANSFORM_ENCR_TYPE_DES_CBC: epp_aed_info.cipher = EVP_des_cbc(); break;
    case EPP_TRANSFORM_ENCR_TYPE_3DES_CBC: epp_aed_info.cipher = EVP_des_ede3_cbc(); break;
    case EPP_TRANSFORM_ENCR_TYPE_AES_CBC_128: epp_aed_info.cipher = EVP_aes_128_cbc(); break;
    case EPP_TRANSFORM_ENCR_TYPE_AES_CBC_192: epp_aed_info.cipher = EVP_aes_192_cbc(); break;
    case EPP_TRANSFORM_ENCR_TYPE_AES_CBC_256: epp_aed_info.cipher = EVP_aes_256_cbc(); break;
    case EPP_TRANSFORM_ENCR_TYPE_AES_GCM_128: epp_aed_info.cipher = EVP_aes_128_gcm(); break;
    case EPP_TRANSFORM_ENCR_TYPE_AES_GCM_192: epp_aed_info.cipher = EVP_aes_192_gcm(); break;
    case EPP_TRANSFORM_ENCR_TYPE_AES_GCM_256: epp_aed_info.cipher = EVP_aes_256_gcm(); break;
    case EPP_TRANSFORM_ENCR_TYPE_AES_CTR_128: epp_aed_info.cipher = EVP_aes_128_ctr(); break;
    case EPP_TRANSFORM_ENCR_TYPE_AES_CTR_192: epp_aed_info.cipher = EVP_aes_192_ctr(); break;
    case EPP_TRANSFORM_ENCR_TYPE_AES_CTR_256: epp_aed_info.cipher = EVP_aes_256_ctr(); break;
    }

    /* initialize en/decryption */
    if(is_encrypt) 
        ret = EVP_EncryptInit_ex(epp_aed_info.ctx,  epp_aed_info.cipher, NULL, keydata, NULL);
    else
        ret = EVP_DecryptInit_ex(epp_aed_info.ctx,  epp_aed_info.cipher, NULL, keydata, NULL);

    if(ret != 1) printf("Failed in EVP_En/DecryptInit_ex(ret=%x)", ret);

    /* disable padding */
    EVP_CIPHER_CTX_set_padding(epp_aed_info.ctx, 0);

   /* initialize context */
    epp_aed_info.hctx = HMAC_CTX_new();
    switch(int_alg){
    case EPP_TRANSFORM_HMAC_TYPE_MD5: epp_aed_info.hmac = EVP_md5(); break;
    case EPP_TRANSFORM_HMAC_TYPE_SHA1: epp_aed_info.hmac = EVP_sha1(); break;
    case EPP_TRANSFORM_HMAC_TYPE_SHA224: epp_aed_info.hmac = EVP_sha224(); break;
    case EPP_TRANSFORM_HMAC_TYPE_SHA256: epp_aed_info.hmac = EVP_sha256(); break;
    case EPP_TRANSFORM_HMAC_TYPE_SHA384: epp_aed_info.hmac = EVP_sha384(); break;
    case EPP_TRANSFORM_HMAC_TYPE_SHA512: epp_aed_info.hmac = EVP_sha512(); break;
    }

    /* initialize hmac context */
    ret = HMAC_Init_ex(epp_aed_info.hctx, int_keydata, int_keylen, epp_aed_info.hmac, NULL);
    if(ret != 1) printf("Failed in HMAC_Init_ex(ret=%x)", ret);

    printf("%s: (completed) spi=%d, is_encrypt=%d, alg=%d, int_alg=%d\n", __FUNCTION__, spi, is_encrypt, enc_alg, int_alg);

    /* insert the contexted into map */
    g_aed_map.insert(std::pair<uint32_t, epp_aed_t>(spi, epp_aed_info));
}

/* dummy function */
void do_dummy(void)
{
    return;
}

/* function for AD-merging */
void do_aed(
    uint32_t spi, uint8_t is_encrypt, 
    uint8_t* iv,
    uint8_t* src, uint32_t slen,
    uint8_t* dst, int* dlen,
    uint8_t* int_src, uint32_t int_slen,
    uint8_t* int_dst, uint8_t* int_dlen,
    int* e_ret 
)
{
    int out_len = 0;
    uint32_t out_hlen = 0;
    int total_len = 0;
    int ret = 0;
    size_t sz;
    uint8_t buffer[64];

    /* find the initialized context */
    std::map<uint32_t, epp_aed_t>::iterator it = g_aed_map.find(spi);

    if(it != g_aed_map.end()){
        if(is_encrypt){ /* encrypt and then MAC */
            /* feed an IV */
            ret = EVP_EncryptInit_ex((it->second).ctx, NULL, NULL, NULL, iv);
            if(ret <=0) printf("Failed in EVP_EncryptInit_ex(ret=%x)", ret);

            /* encryption */
            ret = EVP_EncryptUpdate((it->second).ctx, dst, &out_len, src, slen);
            if(ret <=0) printf("Failed in EVP_EncryptUpdate(ret=%x)", ret);
            total_len += out_len;

            if(out_len < (int) slen){
                ret = EVP_EncryptFinal_ex((it->second).ctx, dst+out_len, &out_len);
                if(ret <=0) printf("Failed in EVP_EncryptFinal_ex(ret=%x)", ret);
                total_len += out_len;
            }
                
            *dlen = total_len;

            /* initialize the context, but reuse the key */
            ret = HMAC_Init_ex((it->second).hctx, NULL, 0, (it->second).hmac, NULL);
            if(ret != 1) printf("Failed in HMAC_Init_ex(ret=%x)", ret);
 
            /* hmac */
            ret = HMAC_Update((it->second).hctx, int_src, int_slen);
            if(ret != 1) printf("Failed in HMAC_Update(ret=%x)", ret);

            ret = HMAC_Final((it->second).hctx, int_dst, &out_hlen);
            if(ret != 1) printf("Failed in HMAC_Final(ret=%x)", ret);

            sz = (*int_dlen ? *int_dlen : out_hlen);
            *int_dlen = (uint8_t)sz;
        }else{ /* MAC then decrypt */
            /* initialize the context, but reuse the key */
            ret = HMAC_Init_ex((it->second).hctx, NULL, 0, (it->second).hmac, NULL);
            if(ret != 1) printf("Failed in HMAC_Init_ex(ret=%x)", ret);
 
            /* hmac */
            ret = HMAC_Update((it->second).hctx, int_src, int_slen);
            if(ret != 1) printf("Failed in HMAC_Update(ret=%x)", ret);

            ret = HMAC_Final((it->second).hctx, buffer, &out_hlen);
            if(ret != 1) printf("Failed in HMAC_Final(ret=%x)", ret);

            sz = (*int_dlen ? *int_dlen : out_hlen);
            ret = memcmp(int_dst, buffer, sz);
            if(e_ret) *e_ret = ret; 

            /* feed an IV */
            ret = EVP_DecryptInit_ex((it->second).ctx, NULL, NULL, NULL, iv);
            if(ret <=0) printf("Failed in EVP_DecryptInit_ex(ret=%x)", ret);
            
            /* decryption */
            ret = EVP_DecryptUpdate((it->second).ctx, dst, &out_len, src, slen);
            if(ret <= 0) printf("Failed in EVP_DecryptUpdate(ret=%x)", ret);
            total_len += out_len;

            if(out_len < (int) slen){
                ret = EVP_DecryptFinal_ex((it->second).ctx, dst+out_len, &out_len);
                if(ret <= 0) printf("Failed in EVP_DecryptFinal_ex(ret=%x)", ret);
                total_len += out_len;
            }

            *dlen = total_len;
        }
#if ENABLE_FORWARDING
	uint8_t* tmp = (uint8_t*)malloc(sizeof(uint8_t) * slen);
	if(tmp != NULL) free(tmp);
#endif 
    }
}

/* function for en/decryption */
void do_cipher(
    uint32_t spi, uint8_t is_encrypt, 
    uint8_t* iv,
    uint8_t* src, uint32_t slen,
    uint8_t* dst, int* dlen
)
{
    int out_len = 0;
    int total_len = 0;
    int ret = 0;

    /* find the initialized context */
    std::map<uint32_t, epp_cipher_t>::iterator it = g_cipher_map.find(spi);

    if(it != g_cipher_map.end()){
        if(is_encrypt){
            /* feed an IV */
            ret = EVP_EncryptInit_ex((it->second).ctx, NULL, NULL, NULL, iv);
            if(ret <=0) printf("Failed in EVP_EncryptInit_ex(ret=%x)", ret);

            /* encryption */
            ret = EVP_EncryptUpdate((it->second).ctx, dst, &out_len, src, slen);
            if(ret <=0) printf("Failed in EVP_EncryptUpdate(ret=%x)", ret);
            total_len += out_len;

            if(out_len < (int) slen){
                ret = EVP_EncryptFinal_ex((it->second).ctx, dst+out_len, &out_len);
                if(ret <=0) printf("Failed in EVP_EncryptFinal_ex(ret=%x)", ret);
                total_len += out_len;
            }
        }
        else{
            /* feed an IV */
            ret = EVP_DecryptInit_ex((it->second).ctx, NULL, NULL, NULL, iv);
            if(ret <=0) printf("Failed in EVP_DecryptInit_ex(ret=%x)", ret);
            
            /* decryption */
            ret = EVP_DecryptUpdate((it->second).ctx, dst, &out_len, src, slen);
            if(ret <= 0) printf("Failed in EVP_DecryptUpdate(ret=%x)", ret);
            total_len += out_len;

            if(out_len < (int) slen){
                ret = EVP_DecryptFinal_ex((it->second).ctx, dst+out_len, &out_len);
                if(ret <= 0) printf("Failed in EVP_DecryptFinal_ex(ret=%x)", ret);
                total_len += out_len;
            }
        }
        *dlen = total_len;
    }
}

/* function for en/decryption */
void do_cipher_gcm(
    uint32_t spi, uint8_t is_encrypt, 
    uint8_t* iv, uint32_t ivlen,
    uint8_t* aad, uint32_t aad_len,
    uint8_t* src, uint32_t slen,
    uint8_t* dst, int* dlen,
    uint8_t* tag, uint8_t taglen,
    int* e_ret
)
{
    int len = 0;
    int ret = 0;

    /* find the initialized context */
    std::map<uint32_t, epp_cipher_t>::iterator it = g_cipher_map.find(spi);

    if(it != g_cipher_map.end()){
        ret = EVP_CIPHER_CTX_ctrl((it->second).ctx,EVP_CTRL_GCM_SET_IVLEN, ivlen, NULL);
        if(ret != 1) printf("Failed in EVP_CIPHER_CTX_ctrl(ret=%x)", ret);

        if(is_encrypt){
            ret = EVP_EncryptInit_ex((it->second).ctx, NULL, NULL, NULL, iv);
            if(ret <=0) printf("Failed in EVP_EncryptInit_ex(ret=%x)", ret);

            /* aad */
            if(aad_len){
                ret = EVP_EncryptUpdate((it->second).ctx, NULL, &len, aad, aad_len);
                if(ret <=0) printf("Failed in EVP_EncryptUpdate(aad, ret=%x)", ret);
            }

            /* encryption */
            ret = EVP_EncryptUpdate((it->second).ctx, dst, &len, src, slen);
            if(ret <=0) printf("Failed in EVP_EncryptUpdate(ret=%x)", ret);

            ret = EVP_EncryptFinal_ex((it->second).ctx, dst+len, &len);
            if(ret <=0) printf("Failed in EVP_EncryptFinal_ex(ret=%x)", ret);

            ret = EVP_CIPHER_CTX_ctrl((it->second).ctx, EVP_CTRL_GCM_GET_TAG, taglen, tag);
            if(ret <=0) printf("Failed in EVP_CIPHER_CTX_ctrl(GET_TAG, ret=%x)", ret);
        }
        else{
            ret = EVP_DecryptInit_ex((it->second).ctx, NULL, NULL, NULL, iv);
            if(ret <=0) printf("Failed in EVP_DecryptInit_ex(ret=%x)", ret);
            
            /* aad */
            if(aad != NULL){
                ret = EVP_DecryptUpdate((it->second).ctx, NULL, &len, aad, aad_len);
                if(ret <=0) printf("Failed in EVP_EncryptUpdate(aad, ret=%x)", ret);
            }

            /* decryption */
            ret = EVP_DecryptUpdate((it->second).ctx, dst, &len, src, slen);
            if(ret <= 0) printf("Failed in EVP_DecryptUpdate(ret=%x)", ret);

            ret = EVP_CIPHER_CTX_ctrl((it->second).ctx, EVP_CTRL_GCM_SET_TAG, taglen, tag);
            if(ret <=0) printf("Failed in EVP_CIPHER_CTX_ctrl(SET_TAG, ret=%x)", ret);

            ret = EVP_DecryptFinal_ex((it->second).ctx, dst+len, &len);
            if(ret <= 0) printf("Failed in EVP_DecryptFinal_ex(ret=%x)", ret);
 
            if(e_ret) *e_ret = ret;

        }
        *dlen = len;
    }else{
        // ocall_print("Failed to find the crypto context for En/Decryption");
    }
}

/* function for hmac */
void do_hmac(
    uint32_t spi,  
    uint8_t* src, uint32_t slen,
    uint8_t* dst, uint32_t* dlen
)
{
    int ret = 0;
    
    /* find the initialized context */
    std::map<uint32_t, epp_hmac_t>::iterator it = g_hmac_map.find(spi);

    if(it != g_hmac_map.end()){
        /* initialize the context, but reuse the key */
        ret = HMAC_Init_ex((it->second).ctx, NULL, 0, (it->second).hmac, NULL);
        if(ret != 1) printf("Failed in HMAC_Init_ex(ret=%x)", ret);
 
        /* hmac */
        ret = HMAC_Update((it->second).ctx, src, slen);
        if(ret != 1) printf("Failed in HMAC_Update(ret=%x)", ret);
        HMAC_Final((it->second).ctx, dst, dlen);
        if(ret != 1) printf("Failed in HMAC_Final(ret=%x)", ret);
    }else{
        ocall_print("Failed to find the crypto context for HMAC");
    }
}
