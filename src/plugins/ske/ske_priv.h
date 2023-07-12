/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
 */
#ifndef __included_ske_priv_h__
#define __included_ske_priv_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>

#include <plugins/ske/ske.h>

#include <vppinfra/hash.h>
#include <vppinfra/elog.h>
#include <vppinfra/error.h>

#include <openssl/rand.h>
#include <openssl/dh.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

/* SGX headers */
#include "Enclave_u.h"
#include "sgx_eid.h"
#include "sgx_urts.h"
#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#define UNUSED(val) (void)(val)
#define TCHAR   char
#define _TCHAR  char
#define _T(str) str

#define ENCLAVE_PATH "/home/libeke.so"

#define SKE_DEBUG_PAYLOAD 1

#define TYPE_SKEYSEED 1
#define TYPE_KEYMAT 2
#define TYPE_AUTHMSG 3
#define TYPE_AUTH1 4
#define TYPE_AUTH2 5

#define IS_PARENT 1
#define IS_CHILD 0

#define EKE_TRANSFORM_ENCR_TYPE_AES_CBC_128 1
#define EKE_TRANSFORM_ENCR_TYPE_AES_CBC_192 2
#define EKE_TRANSFORM_ENCR_TYPE_AES_CBC_256 3

#define EKE_TRANSFORM_PRF_TYPE_PRF_HMAC_SHA1 1
#define EKE_TRANSFORM_PRF_TYPE_PRF_HMAC_SHA2_256 2
#define EKE_TRANSFORM_PRF_TYPE_PRF_HMAC_SHA2_384 3
#define EKE_TRANSFORM_PRF_TYPE_PRF_HMAC_SHA2_512 4

#define EKE_TRANSFORM_INTEG_TYPE_AUTH_HMAC_SHA1_96 1
#define EKE_TRANSFORM_INTEG_TYPE_AUTH_HMAC_SHA1_160 2
#define EKE_TRANSFORM_INTEG_TYPE_AUTH_HMAC_SHA2_256_128 3
#define EKE_TRANSFORM_INTEG_TYPE_AUTH_HMAC_SHA2_384_192 4
#define EKE_TRANSFORM_INTEG_TYPE_AUTH_HMAC_SHA2_512_256 5

#if SKE_DEBUG_PAYLOAD == 1
#define DBG_PLD(my_args...) clib_warning(my_args)
#else
#define DBG_PLD(my_args...)
#endif

typedef enum
{
  SKE_STATE_UNKNOWN,
  SKE_STATE_SA_INIT,
  SKE_STATE_DELETED,
  SKE_STATE_AUTH_FAILED,
  SKE_STATE_AUTHENTICATED,
  SKE_STATE_NOTIFY_AND_DELETE,
  SKE_STATE_TS_UNACCEPTABLE,
  SKE_STATE_NO_PROPOSAL_CHOSEN,
} ske_state_t;

typedef struct
{
  ske_auth_method_t method:8;
  u8 *data;
  u8 hex;			/* hex encoding of the shared secret */
  EVP_PKEY *key;
} ske_auth_t;

typedef enum
{
  SKE_DH_GROUP_MODP = 0,
  SKE_DH_GROUP_ECP = 1,
} ske_dh_group_t;

typedef struct
{
  ske_transform_type_t type;
  union
  {
    u16 transform_id;
    ske_transform_encr_type_t encr_type:16;
    ske_transform_prf_type_t prf_type:16;
    ske_transform_integ_type_t integ_type:16;
    ske_transform_dh_type_t dh_type:16;
    ske_transform_esn_type_t esn_type:16;
  };
  u8 *attrs;
  u16 key_len;
  u16 key_trunc;
  u16 block_size;
  u8 dh_group;
  int nid;
  int mode;
  const char *dh_p;
  const char *dh_g;
  const void *md;
  const void *cipher;
} ske_sa_transform_t;

typedef struct
{
  u8 proposal_num;
  ske_protocol_id_t protocol_id:8;
  u32 spi;
  ske_sa_transform_t *transforms;
} ske_sa_proposal_t;

typedef struct
{
  u8 ts_type;
  u8 protocol_id;
  u16 selector_len;
  u16 start_port;
  u16 end_port;
  ip4_address_t start_addr;
  ip4_address_t end_addr;
} ske_ts_t;

typedef struct
{
  u32 sw_if_index;
  ip4_address_t ip4;
} ske_responder_t;

typedef struct
{
  ske_transform_encr_type_t crypto_alg;
  ske_transform_integ_type_t integ_alg;
  ske_transform_dh_type_t dh_type;
  u32 crypto_key_size;
} ske_transforms_set;


typedef struct
{
  ske_id_type_t type:8;
  u8 *data;
} ske_id_t;

typedef struct
{
  /* sa proposals vectors */
  ske_sa_proposal_t *i_proposals;
  ske_sa_proposal_t *r_proposals;

  /* Traffic Selectors */
  ske_ts_t *tsi;
  ske_ts_t *tsr;

  /* keys */
  u8 *sk_ai;
  u8 *sk_ar;
  u8 *sk_ei;
  u8 *sk_er;
  u32 salt_ei;
  u32 salt_er;

  /* lifetime data */
  f64 time_to_expiration;
  u8 is_expired;
  i8 rekey_retries;
} ske_child_sa_t;

typedef struct
{
  u8 protocol_id;
  u32 spi;			/*for ESP and AH SPI size is 4, for IKE size is 0 */
} ske_delete_t;

typedef struct
{
  u8 protocol_id;
  u32 spi;
  u32 ispi;
  ske_sa_proposal_t *i_proposal;
  ske_sa_proposal_t *r_proposal;
  ske_ts_t *tsi;
  ske_ts_t *tsr;
} ske_rekey_t;

typedef struct
{
  u16 msg_type;
  u8 protocol_id;
  u32 spi;
  u8 *data;
} ske_notify_t;

typedef struct
{
  u8 *name;
  u8 is_enabled;

  ske_auth_t auth;
  ske_id_t loc_id;
  ske_id_t rem_id;
  ske_ts_t loc_ts;
  ske_ts_t rem_ts;
  ske_responder_t responder;
  ske_transforms_set ske_ts;
  ske_transforms_set esp_ts;
  u64 lifetime;
  u64 lifetime_maxdata;
  u32 lifetime_jitter;
  u32 handover;
} ske_profile_t;

typedef struct
{
  ske_state_t state;
  u8 unsupported_cp;
  u8 initial_contact;
  ip4_address_t iaddr;
  ip4_address_t raddr;
  u64 ispi;
  u64 rspi;
  u64 index_spi;
  u8 *i_nonce;
  u8 *r_nonce;

  /* DH data */
  u16 dh_group;
  u8 *dh_shared_key;
  u8 *dh_private_key;
  u8 *i_dh_data;
  u8 *r_dh_data;

  /* sa proposals vectors */
  ske_sa_proposal_t *i_proposals;
  ske_sa_proposal_t *r_proposals;

  /* keys */
  u8 *sk_d;
  u8 *sk_ai;
  u8 *sk_ar;
  u8 *sk_ei;
  u8 *sk_er;
  u8 *sk_pi;
  u8 *sk_pr;

  /* auth */
  ske_auth_t i_auth;
  ske_auth_t r_auth;

  /* ID */
  ske_id_t i_id;
  ske_id_t r_id;

  /* pending deletes */
  ske_delete_t *del;

  /* pending rekeyings */
  ske_rekey_t *rekey;

  /* packet data */
  u8 *last_sa_init_req_packet_data;
  u8 *last_sa_init_res_packet_data;

  /* retransmit */
  u32 last_msg_id;
  u8 *last_res_packet_data;

  u8 is_initiator;
  u32 last_init_msg_id;
  u8 is_profile_index_set;
  u32 profile_index;

  ske_child_sa_t *childs;
} ske_sa_t;


typedef struct
{
  /* pool of SKE Security Associations */
  ske_sa_t *sas;

  /* hash */
  uword *sa_by_rspi;
} ske_main_per_thread_data_t;

typedef struct
{
  /* pool of SKE profiles */
  ske_profile_t *profiles;

  /* vector of supported transform types */
  ske_sa_transform_t *supported_transforms;

  /* hash */
  mhash_t profile_index_by_name;

  /* local private key */
  EVP_PKEY *pkey;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;

  /* pool of SKE Security Associations created in initiator mode */
  ske_sa_t *sais;
  /* hash */
  uword *sa_by_ispi;

  ske_main_per_thread_data_t *per_thread_data;

  /* API message ID base */
  u16 msg_id_base;
} ske_main_t;

extern ske_main_t ske_main;

void ske_sa_free_proposal_vector (ske_sa_proposal_t ** v);
ske_sa_transform_t *ske_sa_get_td_for_type (ske_sa_proposal_t * p,
						ske_transform_type_t type);

/* skev2_crypto.c */
v8 *ske_calc_prf (ske_sa_transform_t * tr, v8 * key, v8 * data);
u8 *ske_calc_prfplus (ske_sa_transform_t * tr, u8 * key, u8 * seed,
			int len);
v8 *ske_calc_integr (ske_sa_transform_t * tr, v8 * key, u8 * data,
		       int len);
v8 *ske_decrypt_data (ske_sa_t * sa, u8 * data, int len);
int ske_encrypt_data (ske_sa_t * sa, v8 * src, u8 * dst);
void ske_generate_dh (ske_sa_t * sa, ske_sa_transform_t * t);
void ske_complete_dh (ske_sa_t * sa, ske_sa_transform_t * t);
int ske_verify_sign (EVP_PKEY * pkey, u8 * sigbuf, u8 * data);
u8 *ske_calc_sign (EVP_PKEY * pkey, u8 * data);
EVP_PKEY *ske_load_cert_file (u8 * file);
EVP_PKEY *ske_load_key_file (u8 * file);
void ske_crypto_init (ske_main_t * km);

/* skev2_payload.c */
typedef struct
{
  u8 first_payload_type;
  u16 last_hdr_off;
  u8 *data;
} ske_payload_chain_t;

#define ske_payload_new_chain(V) vec_validate (V, 0)
#define ske_payload_destroy_chain(V) do { \
  vec_free((V)->data);                 \
  vec_free(V);                         \
} while (0)

void ske_payload_add_notify (ske_payload_chain_t * c, u16 msg_type,
			       u8 * data);
void ske_payload_add_notify_2 (ske_payload_chain_t * c, u16 msg_type,
				 u8 * data, ske_notify_t * notify);
void ske_payload_add_sa (ske_payload_chain_t * c,
			   ske_sa_proposal_t * proposals);
void ske_payload_add_ke (ske_payload_chain_t * c, u16 dh_group,
			   u8 * dh_data);
void ske_payload_add_nonce (ske_payload_chain_t * c, u8 * nonce);
void ske_payload_add_id (ske_payload_chain_t * c, ske_id_t * id,
			   u8 type);
void ske_payload_add_auth (ske_payload_chain_t * c, ske_auth_t * auth);
void ske_payload_add_ts (ske_payload_chain_t * c, ske_ts_t * ts,
			   u8 type);
void ske_payload_add_delete (ske_payload_chain_t * c, ske_delete_t * d);
void ske_payload_chain_add_padding (ske_payload_chain_t * c, int bs);
void ske_parse_vendor_payload (ske_payload_header_t * skep);
ske_sa_proposal_t *ske_parse_sa_payload (ske_payload_header_t * skep);
ske_ts_t *ske_parse_ts_payload (ske_payload_header_t * skep);
ske_delete_t *ske_parse_delete_payload (ske_payload_header_t * skep);
ske_notify_t *ske_parse_notify_payload (ske_payload_header_t * skep);

#endif /* __included_ske_priv_h__ */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
