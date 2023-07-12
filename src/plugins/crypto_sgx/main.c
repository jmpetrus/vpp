/*
 *------------------------------------------------------------------
 * Copyright (c) 2019 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *------------------------------------------------------------------
 */

#include <vlib/vlib.h>
#include <vnet/plugin/plugin.h>
#include <vnet/crypto/crypto.h>
#include <vpp/app/version.h>

/* SGX headers */
#include "Enclave_u.h"
#include "sgx_eid.h"
#include "sgx_urts.h"

/* OpenSSL headers */
#include <openssl/rand.h>

#define ENCLAVE_PATH "/home/libepp.so"
#define MAX_SESSION 2048
#define ENCRYPT 1
#define DECRYPT 0

typedef struct
{
  uint32_t spi;
} spp_data_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  spp_data_t spp_data[MAX_SESSION];
} spp_per_thread_data_t;

sgx_enclave_id_t e_enclave_id = 0;

/* enclave functions */
uint32_t load_enclave()
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    ret = sgx_create_enclave(ENCLAVE_PATH, SGX_DEBUG_FLAG, NULL, NULL, &e_enclave_id, NULL);
    if(ret != SGX_SUCCESS){
        return ret;
    }

    return SGX_SUCCESS;
}

void ocall_print(const char* str){
    clib_warning("OCall: %s", str);
}

static spp_per_thread_data_t *per_thread_data = 0;

#define foreach_spp_crypto_op \
  _(cbc, DES_CBC) \
  _(cbc, 3DES_CBC) \
  _(cbc, AES_128_CBC) \
  _(cbc, AES_192_CBC) \
  _(cbc, AES_256_CBC) \
  _(gcm, AES_128_GCM) \
  _(gcm, AES_192_GCM) \
  _(gcm, AES_256_GCM) \
  _(cbc, AES_128_CTR) \
  _(cbc, AES_192_CTR) \
  _(cbc, AES_256_CTR) \

#define foreach_spp_hmac_op \
  _(MD5) \
  _(SHA1) \
  _(SHA224) \
  _(SHA256) \
  _(SHA384) \
  _(SHA512)

static_always_inline u32
spp_ops_enc_cbc (vlib_main_t * vm, vnet_crypto_op_t * ops[], u32 n_ops)
{
  spp_per_thread_data_t *ptd = vec_elt_at_index (per_thread_data,
						     vm->thread_index);
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;

  u32 i;
  for (i = 0; i < n_ops; i++)
    {
      vnet_crypto_op_t *op = ops[i];
      vnet_crypto_key_t *key = vnet_crypto_get_key (op->key_index);
#if ENABLE_AD
      vnet_crypto_key_t *hkey = vnet_crypto_get_key (op->integ_key_index);
#endif

      int iv_len;
      int out_len;

      if (op->op == VNET_CRYPTO_OP_3DES_CBC_ENC)
	iv_len = 8;
      else
	iv_len = 16;

      if (op->flags & VNET_CRYPTO_OP_FLAG_INIT_IV)
	RAND_bytes (op->iv, iv_len);

      if((ptd->spp_data[op->key_index]).spi == 0){
#if ENABLE_AD
         clib_warning("\nInit AD-merging (enc_key_index=%d, integ_key_index=%d)", 
							op->key_index, op->integ_key_index);
#else
         clib_warning("\nInit encryption (key_index=%d)", op->key_index);
#endif
         (ptd->spp_data[op->key_index]).spi = op->key_index + 1;

#if ENABLE_AD 
          ret = Enclave_aed_init(e_enclave_id,
                                    op->key_index, 
                                    ENCRYPT,                                    
                                    (uint32_t) key->alg,
                                    (uint32_t) hkey->alg,
                                    key->data,
				    hkey->data, vec_len(hkey->data));
#else
          ret = Enclave_cipher_init(e_enclave_id,
                                    op->key_index,
                                    ENCRYPT, 
                                    (uint32_t) key->alg,
                                    key->data);

#endif
          if(ret != SGX_SUCCESS){
              clib_warning("Failed to cipher_init(ENCRYPT)");
          }
      }

#if ENABLE_AD
      ret = Enclave_do_aed(e_enclave_id, op->key_index,
                              ENCRYPT,
                              op->iv, op->src, op->len, op->dst, &out_len,
                              op->integ_src, op->integ_len,
                              op->digest, &(op->digest_len), NULL);
#else
      ret = Enclave_do_cipher(e_enclave_id, op->key_index,
                              ENCRYPT,
                              op->iv, op->src, op->len, op->dst, &out_len);
#endif
      if(ret != SGX_SUCCESS){
          clib_warning("Failed to do_cipher(ENCRYPT)");
      }

      op->status = VNET_CRYPTO_OP_STATUS_COMPLETED;
    }

  return n_ops;
}

static_always_inline u32
spp_ops_dec_cbc (vlib_main_t * vm, vnet_crypto_op_t * ops[], u32 n_ops)
{
  spp_per_thread_data_t *ptd = vec_elt_at_index (per_thread_data,
						     vm->thread_index);
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  u32 i;
#if ENABLE_AD
  u32 n_fail = 0;
#endif

  for (i = 0; i < n_ops; i++)
    {
      vnet_crypto_op_t *op = ops[i];
      vnet_crypto_key_t *key = vnet_crypto_get_key (op->key_index);
      int out_len;
#if ENABLE_AD
      int e_ret = 0;
      vnet_crypto_key_t *hkey = vnet_crypto_get_key (op->integ_key_index);
#endif

      /* initialize a crypto context with key */
      if((ptd->spp_data[op->key_index]).spi == 0){
#if ENABLE_AD
         clib_warning("\nInit AD-merging (dec_key_index=%d, integ_key_index=%d)", 
							op->key_index, op->integ_key_index);
#else
         clib_warning("\nInit decryption (key_index=%d)", op->key_index);
#endif

         (ptd->spp_data[op->key_index]).spi = op->key_index + 1;
#if ENABLE_AD
          ret = Enclave_aed_init(e_enclave_id,
				 op->key_index,
				 DECRYPT,
				 (uint32_t) key->alg,
                                 (uint32_t) hkey->alg,
                                 key->data,
                                 hkey->data, vec_len(hkey->data));
#else
          ret = Enclave_cipher_init(e_enclave_id,
                                    op->key_index,
                                    DECRYPT, 
                                    (uint32_t) key->alg,
                                    key->data);
#endif
          if(ret != SGX_SUCCESS){
              clib_warning("Failed to cipher_init(DECRYPT)");
          }
      }

#if ENABLE_AD
#if TIME_MEASUREMENT 
      u64 start, end, elapsed;
      start = unix_time_now_nsec();

      ret = Enclave_do_dummy(e_enclave_id);

      end = unix_time_now_nsec();
      elapsed = end - start;
      clib_warning("(TIME) Elapsed time (dummy): time=%llu ns", elapsed);
#endif

#if TIME_MEASUREMENT
      start = unix_time_now_nsec();
#endif
      ret = Enclave_do_aed(e_enclave_id, op->key_index,
                           DECRYPT,
                           op->iv, op->src, op->len, op->dst, &out_len,
                           op->integ_src, op->integ_len,
                           op->digest, &(op->digest_len), &e_ret);

#if TIME_MEASUREMENT
      end = unix_time_now_nsec();
      elapsed = end - start;
      clib_warning("(TIME) Elapsed time (crypto): time=%llu ns", elapsed);
#endif
#else
      ret = Enclave_do_cipher(e_enclave_id, op->key_index,
                              DECRYPT,
                              op->iv, op->src, op->len, op->dst, &out_len);
#endif
      if(ret != SGX_SUCCESS){
          clib_warning("Failed to do_cipher(DECRYPT)");
      }

#if ENABLE_AD
      if(e_ret != 0)
       {
           n_fail++;
           op->status = VNET_CRYPTO_OP_STATUS_FAIL_BAD_HMAC;
           continue;
       }
#endif

      op->status = VNET_CRYPTO_OP_STATUS_COMPLETED;
    }
#if ENABLE_AD
  return n_ops - n_fail;
#else
  return n_ops;
#endif
}

static_always_inline u32
spp_ops_enc_gcm (vlib_main_t * vm, vnet_crypto_op_t * ops[], u32 n_ops)
{
  spp_per_thread_data_t *ptd = vec_elt_at_index (per_thread_data,
						     vm->thread_index);
  u32 i;
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;

  for (i = 0; i < n_ops; i++)
    {
      vnet_crypto_op_t *op = ops[i];
      vnet_crypto_key_t *key = vnet_crypto_get_key (op->key_index);
      int out_len;

      /* initialize a crypto context with key */
      if((ptd->spp_data[op->key_index]).spi == 0){
         clib_warning("\nInit encryption for GCM (key_index=%d)", op->key_index);
         (ptd->spp_data[op->key_index]).spi = op->key_index + 1;
          ret = Enclave_cipher_init(e_enclave_id,
                                    op->key_index,
                                    ENCRYPT, 
                                    (uint32_t) key->alg,
                                    key->data);
          if(ret != SGX_SUCCESS){
              clib_warning("Failed to cipher_init(ENCRYPT)");
          }
      }

      if (op->flags & VNET_CRYPTO_OP_FLAG_INIT_IV)
	RAND_bytes (op->iv, 8);

      ret = Enclave_do_cipher_gcm(e_enclave_id, op->key_index,
                              ENCRYPT,
                              op->iv, 12,    
                              (op->aad_len ? op->aad : NULL), op->aad_len,
                              op->src, op->len, op->dst, &out_len,
                              op->tag, op->tag_len, NULL);
      if(ret != SGX_SUCCESS){
          clib_warning("Failed to do_cipher_gcm(ENCRYPT)");
      }

      op->status = VNET_CRYPTO_OP_STATUS_COMPLETED;
    }
  return n_ops;
}

static_always_inline u32
spp_ops_dec_gcm (vlib_main_t * vm, vnet_crypto_op_t * ops[], u32 n_ops)
{
  spp_per_thread_data_t *ptd = vec_elt_at_index (per_thread_data,
						     vm->thread_index);
  u32 i, n_fail = 0;
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  int e_ret = 0;

  for (i = 0; i < n_ops; i++)
    {
      vnet_crypto_op_t *op = ops[i];
      vnet_crypto_key_t *key = vnet_crypto_get_key (op->key_index);
      int out_len;

      /* initialize a crypto context with key */
      if((ptd->spp_data[op->key_index]).spi == 0){
         clib_warning("\nInit decryption for GCM (key_index=%d)", op->key_index);
         
         (ptd->spp_data[op->key_index]).spi = op->key_index + 1;
          ret = Enclave_cipher_init(e_enclave_id,
                                    op->key_index,
                                    DECRYPT, 
                                    (uint32_t) key->alg,
                                    key->data);
          if(ret != SGX_SUCCESS){
              clib_warning("Failed to cipher_init(DECRYPT)");
          }
      }

      ret = Enclave_do_cipher_gcm(e_enclave_id, op->key_index,
                              DECRYPT,
                              op->iv, 12,  
                              (op->aad_len ? op->aad : NULL), op->aad_len,
                              op->src, op->len, op->dst, &out_len,
                              op->tag, op->tag_len, &e_ret);
      if(ret != SGX_SUCCESS){
          clib_warning("Failed to do_cipher_gcm(DECRYPT)");
      }

      if(e_ret > 0)
         op->status = VNET_CRYPTO_OP_STATUS_COMPLETED;
      else{
         n_fail++;
         op->status = VNET_CRYPTO_OP_STATUS_FAIL_BAD_HMAC;
      }
    }
  return n_ops - n_fail;
}

static_always_inline u32
spp_ops_hmac (vlib_main_t * vm, vnet_crypto_op_t * ops[], u32 n_ops)
{
  u8 buffer[64];
  spp_per_thread_data_t *ptd = vec_elt_at_index (per_thread_data,
						     vm->thread_index);
  u32 i, n_fail = 0;
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;

  for (i = 0; i < n_ops; i++)
    {
      vnet_crypto_op_t *op = ops[i];
      size_t sz = 0;
      vnet_crypto_key_t *key = vnet_crypto_get_key (op->key_index);
      u32 out_len = 0;

      if((ptd->spp_data[op->key_index]).spi == 0){
         clib_warning("\nInit hmac(key_index=%d)", op->key_index);
         (ptd->spp_data[op->key_index]).spi = op->key_index;
          ret = Enclave_hmac_init(e_enclave_id,
                                    op->key_index, 
                                    (uint32_t) key->alg,
                                    key->data, vec_len(key->data));
          if(ret != SGX_SUCCESS){
              clib_warning("Failed to hmac_init()");
          }
      }

      ret = Enclave_do_hmac(e_enclave_id, 
                            op->key_index, 
                            op->src, op->len,
                            buffer, &out_len);
      if(ret != SGX_SUCCESS){
          clib_warning("Failed to do_hmac()");
      }

      sz = (op->digest_len ? op->digest_len : (size_t) out_len);

      if (op->flags & VNET_CRYPTO_OP_FLAG_HMAC_CHECK)
	{
	  if ((memcmp (op->digest, buffer, sz)))
	    {
	      n_fail++;
	      op->status = VNET_CRYPTO_OP_STATUS_FAIL_BAD_HMAC;
	      continue;
	    }
	}
      else
	clib_memcpy_fast (op->digest, buffer, sz);
      op->status = VNET_CRYPTO_OP_STATUS_COMPLETED;
    }
  return n_ops - n_fail;
}

#define _(m, a) \
static u32 \
spp_ops_enc_##a (vlib_main_t * vm, vnet_crypto_op_t * ops[], u32 n_ops) \
{ return spp_ops_enc_##m (vm, ops, n_ops); } \
\
u32 \
spp_ops_dec_##a (vlib_main_t * vm, vnet_crypto_op_t * ops[], u32 n_ops) \
{ return spp_ops_dec_##m (vm, ops, n_ops); }

foreach_spp_crypto_op;
#undef _

#define _(a) \
static u32 \
spp_ops_hmac_##a (vlib_main_t * vm, vnet_crypto_op_t * ops[], u32 n_ops) \
{ return spp_ops_hmac (vm, ops, n_ops); } \

foreach_spp_hmac_op;
#undef _


clib_error_t *
crypto_spp_init (vlib_main_t * vm)
{
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  spp_per_thread_data_t *ptd;
  u8 *seed_data = 0;
  time_t t;
  pid_t pid;

  /* enclave loading */
  if(load_enclave() != SGX_SUCCESS){
      clib_warning("Failed to load enclave");
  }
  clib_warning("Succeed to load enclave");

  u32 eidx = vnet_crypto_register_engine (vm, "spp", 50, "Crypto SGX");

#define _(m, a) \
  vnet_crypto_register_ops_handler (vm, eidx, VNET_CRYPTO_OP_##a##_ENC, \
				    spp_ops_enc_##a); \
  vnet_crypto_register_ops_handler (vm, eidx, VNET_CRYPTO_OP_##a##_DEC, \
				    spp_ops_dec_##a);

  foreach_spp_crypto_op;
#undef _

#define _(a) \
  vnet_crypto_register_ops_handler (vm, eidx, VNET_CRYPTO_OP_##a##_HMAC, \
				    spp_ops_hmac_##a); \

  foreach_spp_hmac_op;
#undef _

  vec_validate_aligned (per_thread_data, tm->n_vlib_mains - 1,
			CLIB_CACHE_LINE_BYTES);

  vec_foreach (ptd, per_thread_data)
  {
#if 0
    ptd->evp_cipher_ctx = EVP_CIPHER_CTX_new ();
    ptd->hmac_ctx = HMAC_CTX_new ();
#endif
  }

  t = time (NULL);
  pid = getpid ();
  vec_add (seed_data, &t, sizeof (t));
  vec_add (seed_data, &pid, sizeof (pid));
  vec_add (seed_data, seed_data, sizeof (seed_data));

  RAND_seed ((const void *) seed_data, vec_len (seed_data));
  vec_free (seed_data);

  return 0;
}

/* *INDENT-OFF* */
VLIB_INIT_FUNCTION (crypto_spp_init) =
{
  .runs_after = VLIB_INITS ("vnet_crypto_init"),
};
/* *INDENT-ON* */


/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "SPP Crypto Engine",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
