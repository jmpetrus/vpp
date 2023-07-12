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

#include <vlib/vlib.h>
#include <vlib/unix/plugin.h>
#include <vpp/app/version.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vppinfra/error.h>
#include <vppinfra/random.h>
#include <vppinfra/time.h>
#include <vnet/udp/udp.h>
#include <vnet/ipsec/ipsec.h>
#include <plugins/ske/ske.h>
#include <plugins/ske/ske_priv.h>
#include <openssl/sha.h>

ske_main_t ske_main;

sgx_enclave_id_t e_enclave_id = 0;

/* enclave functions */
uint32_t load_enclave()
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    ret = sgx_create_enclave(ENCLAVE_PATH, SGX_DEBUG_FLAG, NULL, NULL, &e_enclave_id, NULL);
    if (ret != SGX_SUCCESS) {
                return ret;
    }

    return SGX_SUCCESS;
}

void ocall_print(const char* str){
    clib_warning("OCall: %s", str);
}

static int ske_delete_tunnel_interface (vnet_main_t * vnm,
					  ske_sa_t * sa,
					  ske_child_sa_t * child);

#define ske_set_state(sa, v) do { \
    (sa)->state = v; \
    clib_warning("sa state changed to " #v); \
  } while(0);

typedef struct
{
  u32 next_index;
  u32 sw_if_index;
} ske_trace_t;

static u8 *
format_ske_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ske_trace_t *t = va_arg (*args, ske_trace_t *);

  s = format (s, "ske: sw_if_index %d, next index %d",
	      t->sw_if_index, t->next_index);
  return s;
}

static vlib_node_registration_t ske_node;

#define foreach_ske_error \
_(PROCESSED, "SKE packets processed") \
_(IKE_SA_INIT_RETRANSMIT, "IKE_SA_INIT retransmit ") \
_(IKE_SA_INIT_IGNORE, "IKE_SA_INIT ignore (IKE SA already auth)") \
_(IKE_REQ_RETRANSMIT, "IKE request retransmit") \
_(IKE_REQ_IGNORE, "IKE request ignore (old msgid)") \
_(NOT_SKE, "Non SKE packets received")

typedef enum
{
#define _(sym,str) SKE_ERROR_##sym,
  foreach_ske_error
#undef _
    SKE_N_ERROR,
} ske_error_t;

static char *ske_error_strings[] = {
#define _(sym,string) string,
  foreach_ske_error
#undef _
};

typedef enum
{
  SKE_NEXT_IP4_LOOKUP,
  SKE_NEXT_ERROR_DROP,
  SKE_N_NEXT,
} ske_next_t;

static ske_sa_transform_t *
ske_find_transform_data (ske_sa_transform_t * t)
{
  ske_main_t *km = &ske_main;
  ske_sa_transform_t *td;

  vec_foreach (td, km->supported_transforms)
  {
    if (td->type != t->type)
      continue;

    if (td->transform_id != t->transform_id)
      continue;

    if (td->type == SKE_TRANSFORM_TYPE_ENCR)
      {
	if (vec_len (t->attrs) != 4 || t->attrs[0] != 0x80
	    || t->attrs[1] != 14)
	  continue;

	if (((t->attrs[2] << 8 | t->attrs[3]) / 8) != td->key_len)
	  continue;
      }
    return td;
  }
  return 0;
}

static ske_sa_proposal_t *
ske_select_proposal (ske_sa_proposal_t * proposals,
		       ske_protocol_id_t prot_id)
{
  ske_sa_proposal_t *rv = 0;
  ske_sa_proposal_t *proposal;
  ske_sa_transform_t *transform, *new_t;
  u8 mandatory_bitmap, optional_bitmap;

  if (prot_id == SKE_PROTOCOL_IKE)
    {
      mandatory_bitmap = (1 << SKE_TRANSFORM_TYPE_ENCR) |
	(1 << SKE_TRANSFORM_TYPE_PRF) |
	(1 << SKE_TRANSFORM_TYPE_INTEG) | (1 << SKE_TRANSFORM_TYPE_DH);
      optional_bitmap = mandatory_bitmap;
    }
  else if (prot_id == SKE_PROTOCOL_ESP)
    {
      mandatory_bitmap = (1 << SKE_TRANSFORM_TYPE_ENCR) |
	(1 << SKE_TRANSFORM_TYPE_ESN);
      optional_bitmap = mandatory_bitmap |
	(1 << SKE_TRANSFORM_TYPE_INTEG) | (1 << SKE_TRANSFORM_TYPE_DH);
    }
  else if (prot_id == SKE_PROTOCOL_AH)
    {
      mandatory_bitmap = (1 << SKE_TRANSFORM_TYPE_INTEG) |
	(1 << SKE_TRANSFORM_TYPE_ESN);
      optional_bitmap = mandatory_bitmap | (1 << SKE_TRANSFORM_TYPE_DH);
    }
  else
    return 0;

  vec_add2 (rv, proposal, 1);

  vec_foreach (proposal, proposals)
  {
    u8 bitmap = 0;
    if (proposal->protocol_id != prot_id)
      continue;

    vec_foreach (transform, proposal->transforms)
    {
      if ((1 << transform->type) & bitmap)
	continue;

      if (ske_find_transform_data (transform))
	{
	  bitmap |= 1 << transform->type;
	  vec_add2 (rv->transforms, new_t, 1);
	  clib_memcpy_fast (new_t, transform, sizeof (*new_t));
	  new_t->attrs = vec_dup (transform->attrs);
	}
    }

    clib_warning ("bitmap is %x mandatory is %x optional is %x",
		  bitmap, mandatory_bitmap, optional_bitmap);

    if ((bitmap & mandatory_bitmap) == mandatory_bitmap &&
	(bitmap & ~optional_bitmap) == 0)
      {
	rv->proposal_num = proposal->proposal_num;
	rv->protocol_id = proposal->protocol_id;
	RAND_bytes ((u8 *) & rv->spi, sizeof (rv->spi));
	goto done;
      }
    else
      {
	vec_free (rv->transforms);
      }
  }

  vec_free (rv);
done:
  return rv;
}

ske_sa_transform_t *
ske_sa_get_td_for_type (ske_sa_proposal_t * p,
			  ske_transform_type_t type)
{
  ske_sa_transform_t *t;

  if (!p)
    return 0;

  vec_foreach (t, p->transforms)
  {
    if (t->type == type)
      return ske_find_transform_data (t);
  }
  return 0;
}

ske_child_sa_t *
ske_sa_get_child (ske_sa_t * sa, u32 spi, ske_protocol_id_t prot_id,
		    int by_initiator)
{
  ske_child_sa_t *c;
  vec_foreach (c, sa->childs)
  {
    ske_sa_proposal_t *proposal =
      by_initiator ? &c->i_proposals[0] : &c->r_proposals[0];
    if (proposal && proposal->spi == spi && proposal->protocol_id == prot_id)
      return c;
  }

  return 0;
}

void
ske_sa_free_proposal_vector (ske_sa_proposal_t ** v)
{
  ske_sa_proposal_t *p;
  ske_sa_transform_t *t;

  if (!*v)
    return;

  vec_foreach (p, *v)
  {
    vec_foreach (t, p->transforms)
    {
      vec_free (t->attrs);
    }
    vec_free (p->transforms);
  }
  vec_free (*v);
};

static void
ske_sa_free_all_child_sa (ske_child_sa_t ** childs)
{
  ske_child_sa_t *c;
  vec_foreach (c, *childs)
  {
    ske_sa_free_proposal_vector (&c->r_proposals);
    ske_sa_free_proposal_vector (&c->i_proposals);
    vec_free (c->sk_ai);
    vec_free (c->sk_ar);
    vec_free (c->sk_ei);
    vec_free (c->sk_er);
  }

  vec_free (*childs);
}

static void
ske_sa_del_child_sa (ske_sa_t * sa, ske_child_sa_t * child)
{
  ske_sa_free_proposal_vector (&child->r_proposals);
  ske_sa_free_proposal_vector (&child->i_proposals);
  vec_free (child->sk_ai);
  vec_free (child->sk_ar);
  vec_free (child->sk_ei);
  vec_free (child->sk_er);

  vec_del1 (sa->childs, child - sa->childs);
}

static void
ske_sa_free_all_vec (ske_sa_t * sa)
{
  vec_free (sa->i_nonce);
  vec_free (sa->i_dh_data);
  vec_free (sa->dh_shared_key);
  vec_free (sa->dh_private_key);

  ske_sa_free_proposal_vector (&sa->r_proposals);
  ske_sa_free_proposal_vector (&sa->i_proposals);

  vec_free (sa->sk_d);
  vec_free (sa->sk_ai);
  vec_free (sa->sk_ar);
  vec_free (sa->sk_ei);
  vec_free (sa->sk_er);
  vec_free (sa->sk_pi);
  vec_free (sa->sk_pr);

  vec_free (sa->i_id.data);
  vec_free (sa->i_auth.data);
  vec_free (sa->r_id.data);
  vec_free (sa->r_auth.data);
  if (sa->r_auth.key)
    EVP_PKEY_free (sa->r_auth.key);

  vec_free (sa->del);

  ske_sa_free_all_child_sa (&sa->childs);
}

static void
ske_delete_sa (ske_sa_t * sa)
{
  ske_main_t *km = &ske_main;
  u32 thread_index = vlib_get_thread_index ();
  uword *p;

  ske_sa_free_all_vec (sa);

  p = hash_get (km->per_thread_data[thread_index].sa_by_rspi, sa->rspi);
  if (p)
    {
      hash_unset (km->per_thread_data[thread_index].sa_by_rspi, sa->rspi);
      pool_put (km->per_thread_data[thread_index].sas, sa);
    }
}

static void
ske_generate_sa_init_data (ske_sa_t * sa)
{
  ske_sa_transform_t *t = 0, *t2;
  ske_main_t *km = &ske_main;
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;

  if (sa->dh_group == SKE_TRANSFORM_DH_TYPE_NONE)
    {
      return;
    }

  /* check if received DH group is on our list of supported groups */
  vec_foreach (t2, km->supported_transforms)
  {
    if (t2->type == SKE_TRANSFORM_TYPE_DH && sa->dh_group == t2->dh_type)
      {
	t = t2;
	break;
      }
  }

  if (!t)
    {
      clib_warning ("unknown dh data group %u (data len %u)", sa->dh_group,
		    vec_len (sa->i_dh_data));
      sa->dh_group = SKE_TRANSFORM_DH_TYPE_NONE;
      return;
    }

  if (sa->is_initiator)
    {
      /* generate rspi */
      RAND_bytes ((u8 *) & sa->ispi, 8);
   
      /* generate nonce */
      sa->i_nonce = vec_new (u8, SKE_NONCE_SIZE);
      RAND_bytes ((u8 *) sa->i_nonce, SKE_NONCE_SIZE);
    }
  else
    {
      /* generate rspi */
      RAND_bytes ((u8 *) & sa->rspi, 8);

      /* generate nonce */
      sa->r_nonce = vec_new (u8, SKE_NONCE_SIZE);
      RAND_bytes ((u8 *) sa->r_nonce, SKE_NONCE_SIZE);
    }

   clib_warning ("[SKE] sa->is_initiator=%d, sa->ispi=0x%x, sa->rspi=0x%x",
                  sa->is_initiator, sa->ispi, sa->rspi);
   sa->index_spi = sa->is_initiator ? sa->ispi : sa->rspi; /* TODO - find a better solution for multi-tunnels */
   clib_warning ("[SKE] sa->is_initiator=%d, sa->index_spi=%llu", 
                  sa->is_initiator, sa->index_spi);

   /* initialize SGX session */
   ret = Enclave_init_session(e_enclave_id, sa->index_spi);
   if(ret != SGX_SUCCESS){
      clib_warning("Failed to initialize an SGX session");
      return;
   }
   else 
      clib_warning("Succeed to initalize an SGX session");

  /* generate dh keys */
  ske_generate_dh (sa, t);

}

static void
ske_complete_sa_data (ske_sa_t * sa, ske_sa_t * sai)
{
  ske_sa_transform_t *t = 0, *t2;
  ske_main_t *km = &ske_main;


  /*move some data to the new SA */
#define _(A) ({void* __tmp__ = (A); (A) = 0; __tmp__;})
  sa->i_nonce = _(sai->i_nonce);
  sa->i_dh_data = _(sai->i_dh_data);
  sa->dh_private_key = _(sai->dh_private_key);
  sa->iaddr.as_u32 = sai->iaddr.as_u32;
  sa->raddr.as_u32 = sai->raddr.as_u32;
  sa->is_initiator = sai->is_initiator;
  sa->index_spi = sai->index_spi;
  sa->i_id.type = sai->i_id.type;
  sa->profile_index = sai->profile_index;
  sa->is_profile_index_set = sai->is_profile_index_set;
  sa->i_id.data = _(sai->i_id.data);
  sa->i_auth.method = sai->i_auth.method;
  sa->i_auth.hex = sai->i_auth.hex;
  sa->i_auth.data = _(sai->i_auth.data);
  sa->i_auth.key = _(sai->i_auth.key);
  sa->last_sa_init_req_packet_data = _(sai->last_sa_init_req_packet_data);
  sa->childs = _(sai->childs);
#undef _


  if (sa->dh_group == SKE_TRANSFORM_DH_TYPE_NONE)
    {
      return;
    }

  /* check if received DH group is on our list of supported groups */
  vec_foreach (t2, km->supported_transforms)
  {
    if (t2->type == SKE_TRANSFORM_TYPE_DH && sa->dh_group == t2->dh_type)
      {
	t = t2;
	break;
      }
  }

  if (!t)
    {
      clib_warning ("unknown dh data group %u (data len %u)", sa->dh_group,
		    vec_len (sa->i_dh_data));
      sa->dh_group = SKE_TRANSFORM_DH_TYPE_NONE;
      return;
    }


  /* generate dh keys */
  ske_complete_dh (sa, t);

}

static void
ske_calc_keys (ske_sa_t * sa)
{
  u8 *tmp;
  /* calculate SKEYSEED = prf(Ni | Nr, g^ir) */
  u8 *skeyseed = 0;
  u8 *s = 0;
  u16 integ_key_len = 0;
  ske_sa_transform_t *tr_encr, *tr_prf, *tr_integ;
  tr_encr =
    ske_sa_get_td_for_type (sa->r_proposals, SKE_TRANSFORM_TYPE_ENCR);
  tr_prf =
    ske_sa_get_td_for_type (sa->r_proposals, SKE_TRANSFORM_TYPE_PRF);
  tr_integ =
    ske_sa_get_td_for_type (sa->r_proposals, SKE_TRANSFORM_TYPE_INTEG);

  if(tr_integ)
    integ_key_len = tr_integ->key_len;

  vec_append (s, sa->i_nonce);
  vec_append (s, sa->r_nonce);

  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  skeyseed = vec_new(u8, tr_prf->key_trunc);
  u32 out_len = 0;

#if TIME_MEASUREMENT /* time measurement */
  u64 start, end, start_ns, end_ns;
  start = clib_cpu_time_now();
  start_ns = unix_time_now_nsec();
#endif

  ret = Enclave_calc_prf(e_enclave_id, 
			sa->index_spi, TYPE_SKEYSEED,  tr_prf->mode, 
                        sa->is_initiator,
                        tr_prf->key_trunc, s, vec_len(s), skeyseed, &out_len);
  if(ret != SGX_SUCCESS){
    clib_warning("Failed to calc_prf(SKEYSEED)");
    return;
  }
#if DEBUG_SUCCEED
  else{
    clib_warning("Succeed to calc_prf(SKEYSEED)");
  }
#endif

#if TIME_MEASUREMENT /* time measurement */
  end = clib_cpu_time_now();
  end_ns = unix_time_now_nsec();
  clib_warning("(TIME) Elapsed time: cycles=%llu, clock=%llu ns", 
                 end - start, end_ns - start_ns);
#endif

  /* Calculate S = Ni | Nr | SPIi | SPIr */
  u64 *spi;
  vec_add2 (s, tmp, 2 * sizeof (*spi));
  spi = (u64 *) tmp;
  spi[0] = clib_host_to_net_u64 (sa->ispi);
  spi[1] = clib_host_to_net_u64 (sa->rspi);

  /* calculate PRFplus */
  u8 *keymat;
  int len = tr_prf->key_trunc +	/* SK_d */
    integ_key_len * 2 +	        /* SK_ai, SK_ar */
    tr_encr->key_len * 2 +	/* SK_ei, SK_er */
    tr_prf->key_len * 2;	/* SK_pi, SK_pr */

  keymat = vec_new(u8, len);

#if TIME_MEASUREMENT /* time measurement */
  start = clib_cpu_time_now();
  start_ns = unix_time_now_nsec();
#endif

  ret = Enclave_calc_prfplus(e_enclave_id, sa->index_spi, 
                             IS_PARENT, tr_prf->mode, s, vec_len(s), 
                             tr_prf->key_trunc,
                             tr_integ->key_len,
                             tr_encr->key_len,
                             tr_prf->key_len
#if 1 /* DEBUG */
			     , keymat
#endif
        );
  if(ret != SGX_SUCCESS){
    clib_warning("Failed to calc_prf(KEYMAT)");
    return;
  }
#if DEBUG_SUCCEED
  else
    clib_warning("Succeed to calc_prf(KEYMAT)");
#endif

#if TIME_MEASUREMENT /* time measurement */
  end = clib_cpu_time_now();
  end_ns = unix_time_now_nsec();
  clib_warning("(TIME) Elapsed time: cycles=%llu, clock=%llu ns", 
                 end - start, end_ns - start_ns);
#endif


  vec_free (skeyseed);
  vec_free (s);

  int pos = 0;

  /* SK_d */
  sa->sk_d = vec_new (u8, tr_prf->key_trunc);
  clib_memcpy_fast (sa->sk_d, keymat + pos, tr_prf->key_trunc);
  pos += tr_prf->key_trunc;

  if(integ_key_len)
    {
      /* SK_ai */
      sa->sk_ai = vec_new (u8, integ_key_len);
      clib_memcpy_fast (sa->sk_ai, keymat + pos, integ_key_len);
      pos += integ_key_len;

      /* SK_ar */
      sa->sk_ar = vec_new (u8, integ_key_len);
      clib_memcpy_fast (sa->sk_ar, keymat + pos, integ_key_len);
      pos += integ_key_len;
    }

  /* SK_ei */
  sa->sk_ei = vec_new (u8, tr_encr->key_len);
  clib_memcpy_fast (sa->sk_ei, keymat + pos, tr_encr->key_len);
  pos += tr_encr->key_len;

  /* SK_er */
  sa->sk_er = vec_new (u8, tr_encr->key_len);
  clib_memcpy_fast (sa->sk_er, keymat + pos, tr_encr->key_len);
  pos += tr_encr->key_len;

  /* SK_pi */
  sa->sk_pi = vec_new (u8, tr_prf->key_len);
  clib_memcpy_fast (sa->sk_pi, keymat + pos, tr_prf->key_len);
  pos += tr_prf->key_len;

  /* SK_pr */
  sa->sk_pr = vec_new (u8, tr_prf->key_len);
  clib_memcpy_fast (sa->sk_pr, keymat + pos, tr_prf->key_len);
  pos += tr_prf->key_len;

  vec_free (keymat);
}

static void
ske_calc_child_keys (ske_sa_t * sa, ske_child_sa_t * child)
{
  u8 *s = 0;
  u16 integ_key_len = 0;
  u8 salt_len = 0;

  ske_sa_transform_t *tr_prf, *ctr_encr, *ctr_integ;
  tr_prf =
    ske_sa_get_td_for_type (sa->r_proposals, SKE_TRANSFORM_TYPE_PRF);
  ctr_encr =
    ske_sa_get_td_for_type (child->r_proposals, SKE_TRANSFORM_TYPE_ENCR);
  ctr_integ =
    ske_sa_get_td_for_type (child->r_proposals, SKE_TRANSFORM_TYPE_INTEG);

  if(ctr_integ)
    integ_key_len = ctr_integ->key_len;
  else
    salt_len = sizeof(u32);

  vec_append (s, sa->i_nonce);
  vec_append (s, sa->r_nonce);
  /* calculate PRFplus */
  u8 *keymat;
  int len = ctr_encr->key_len * 2 + integ_key_len * 2 + salt_len * 2;

  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  keymat = vec_new(u8, len);

#if TIME_MEASUREMENT /* time measurement */
  u64 start, end, start_ns, end_ns;
  start = clib_cpu_time_now();
  start_ns = unix_time_now_nsec();
#endif


  ret = Enclave_calc_prfplus(e_enclave_id, sa->index_spi, 
                             IS_CHILD, tr_prf->mode, s, vec_len(s), 
                             tr_prf->key_trunc,
                             (ctr_integ ? integ_key_len : salt_len),
                             ctr_encr->key_len,
                             0
#if 1 /* DEBUG */
			     , keymat
#endif
        );
  if(ret != SGX_SUCCESS){
    clib_warning("Failed to calc_prf(KEYMAT)");
    return;
  }
#if DEBUG_SUCCEED
  else
    clib_warning("Succeed to calc_prf(KEYMAT)");
#endif

#if TIME_MEASUREMENT /* time measurement */
  end = clib_cpu_time_now();
  end_ns = unix_time_now_nsec();
  clib_warning("(TIME) Elapsed time: cycles=%llu, clock=%llu ns", 
                 end - start, end_ns - start_ns);
#endif


  int pos = 0;

  /* SK_ei */
  child->sk_ei = vec_new (u8, ctr_encr->key_len);
  clib_memcpy_fast (child->sk_ei, keymat + pos, ctr_encr->key_len);
  pos += ctr_encr->key_len;

  if(ctr_integ)
    {
      /* SK_ai */
      child->sk_ai = vec_new (u8, ctr_integ->key_len);
      clib_memcpy_fast (child->sk_ai, keymat + pos, ctr_integ->key_len);
      pos += ctr_integ->key_len;
    }
  else
    {
      clib_memcpy(&child->salt_ei, keymat + pos, salt_len);
      pos += salt_len;
    }

  /* SK_er */
  child->sk_er = vec_new (u8, ctr_encr->key_len);
  clib_memcpy_fast (child->sk_er, keymat + pos, ctr_encr->key_len);
  pos += ctr_encr->key_len;

  if(ctr_integ)
    {
      /* SK_ar */
      child->sk_ar = vec_new (u8, ctr_integ->key_len);
      clib_memcpy_fast (child->sk_ar, keymat + pos, ctr_integ->key_len);
      pos += ctr_integ->key_len;
    }
  else
    {
      clib_memcpy(&child->salt_er, keymat+pos, salt_len);
      pos += salt_len;
    }

  ASSERT (pos == len);

  vec_free (keymat);
}

static void
ske_process_sa_init_req (vlib_main_t * vm, ske_sa_t * sa,
			   ske_header_t * ske)
{
  int p = 0;
  u32 len = clib_net_to_host_u32 (ske->length);
  u8 payload = ske->nextpayload;

  clib_warning ("ispi %lx rspi %lx nextpayload %x version %x "
		"exchange %x flags %x msgid %x length %u",
		clib_net_to_host_u64 (ske->ispi),
		clib_net_to_host_u64 (ske->rspi),
		payload, ske->version,
		ske->exchange, ske->flags,
		clib_net_to_host_u32 (ske->msgid), len);

  sa->ispi = clib_net_to_host_u64 (ske->ispi);

  /* store whole IKE payload - needed for PSK auth */
  vec_free (sa->last_sa_init_req_packet_data);
  vec_add (sa->last_sa_init_req_packet_data, ske, len);

  while (p < len && payload != SKE_PAYLOAD_NONE)
    {
      ske_payload_header_t *skep = (ske_payload_header_t *) & ske->payload[p];
      u32 plen = clib_net_to_host_u16 (skep->length);

      if (plen < sizeof (ske_payload_header_t))
	return;

      if (payload == SKE_PAYLOAD_SA)
	{
	  ske_sa_free_proposal_vector (&sa->i_proposals);
	  sa->i_proposals = ske_parse_sa_payload (skep);
	}
      else if (payload == SKE_PAYLOAD_KE)
	{
	  ske_ke_payload_header_t *ke = (ske_ke_payload_header_t *) skep;
	  sa->dh_group = clib_net_to_host_u16 (ke->dh_group);
	  vec_free (sa->i_dh_data);
	  vec_add (sa->i_dh_data, ke->payload, plen - sizeof (*ke));
	}
      else if (payload == SKE_PAYLOAD_NONCE)
	{
	  vec_free (sa->i_nonce);
	  vec_add (sa->i_nonce, skep->payload, plen - sizeof (*skep));
	}
      else if (payload == SKE_PAYLOAD_NOTIFY)
	{
	  ske_notify_t *n = ske_parse_notify_payload (skep);
	  vec_free (n);
	}
      else if (payload == SKE_PAYLOAD_VENDOR)
	{
	  ske_parse_vendor_payload (skep);
	}
      else
	{
	  clib_warning ("unknown payload %u flags %x length %u", payload,
			skep->flags, plen);
	  if (skep->flags & SKE_PAYLOAD_FLAG_CRITICAL)
	    {
	      ske_set_state (sa, SKE_STATE_NOTIFY_AND_DELETE);
	      sa->unsupported_cp = payload;
	      return;
	    }
	}

      payload = skep->nextpayload;
      p += plen;
    }

  ske_set_state (sa, SKE_STATE_SA_INIT);
}

static void
ske_process_sa_init_resp (vlib_main_t * vm, ske_sa_t * sa,
			    ske_header_t * ske)
{
  int p = 0;
  u32 len = clib_net_to_host_u32 (ske->length);
  u8 payload = ske->nextpayload;

  clib_warning ("ispi %lx rspi %lx nextpayload %x version %x "
		"exchange %x flags %x msgid %x length %u",
		clib_net_to_host_u64 (ske->ispi),
		clib_net_to_host_u64 (ske->rspi),
		payload, ske->version,
		ske->exchange, ske->flags,
		clib_net_to_host_u32 (ske->msgid), len);

  sa->ispi = clib_net_to_host_u64 (ske->ispi);
  sa->rspi = clib_net_to_host_u64 (ske->rspi);

  /* store whole IKE payload - needed for PSK auth */
  vec_free (sa->last_sa_init_res_packet_data);
  vec_add (sa->last_sa_init_res_packet_data, ske, len);

  while (p < len && payload != SKE_PAYLOAD_NONE)
    {
      ske_payload_header_t *skep = (ske_payload_header_t *) & ske->payload[p];
      u32 plen = clib_net_to_host_u16 (skep->length);

      if (plen < sizeof (ske_payload_header_t))
	return;

      if (payload == SKE_PAYLOAD_SA)
	{
	  ske_sa_free_proposal_vector (&sa->r_proposals);
	  sa->r_proposals = ske_parse_sa_payload (skep);
	  if (sa->r_proposals)
	    {
	      ske_set_state (sa, SKE_STATE_SA_INIT);
	      ske->msgid =
		clib_host_to_net_u32 (clib_net_to_host_u32 (ske->msgid) + 1);
	    }
	}
      else if (payload == SKE_PAYLOAD_KE)
	{
	  ske_ke_payload_header_t *ke = (ske_ke_payload_header_t *) skep;
	  sa->dh_group = clib_net_to_host_u16 (ke->dh_group);
	  vec_free (sa->r_dh_data);
	  vec_add (sa->r_dh_data, ke->payload, plen - sizeof (*ke));
	}
      else if (payload == SKE_PAYLOAD_NONCE)
	{
	  vec_free (sa->r_nonce);
	  vec_add (sa->r_nonce, skep->payload, plen - sizeof (*skep));
	}
      else if (payload == SKE_PAYLOAD_NOTIFY)
	{
	  ske_notify_t *n = ske_parse_notify_payload (skep);
	  vec_free (n);
	}
      else if (payload == SKE_PAYLOAD_VENDOR)
	{
	  ske_parse_vendor_payload (skep);
	}
      else
	{
	  clib_warning ("unknown payload %u flags %x length %u", payload,
			skep->flags, plen);
	  if (skep->flags & SKE_PAYLOAD_FLAG_CRITICAL)
	    {
	      ske_set_state (sa, SKE_STATE_NOTIFY_AND_DELETE);
	      sa->unsupported_cp = payload;
	      return;
	    }
	}

      payload = skep->nextpayload;
      p += plen;
    }
}

static u8 *
ske_decrypt_sk_payload (ske_sa_t * sa, ske_header_t * ske, u8 * payload)
{
  int p = 0;
  u8 last_payload = 0;
  u8 *hmac = 0;
  u32 len = clib_net_to_host_u32 (ske->length);
  ske_payload_header_t *skep = 0;
  u32 plen = 0;
  ske_sa_transform_t *tr_integ;
  tr_integ =
    ske_sa_get_td_for_type (sa->r_proposals, SKE_TRANSFORM_TYPE_INTEG);

  while (p < len &&
	 *payload != SKE_PAYLOAD_NONE && last_payload != SKE_PAYLOAD_SK)
    {
      skep = (ske_payload_header_t *) & ske->payload[p];
      plen = clib_net_to_host_u16 (skep->length);

      if (plen < sizeof (*skep))
	return 0;

      if (*payload == SKE_PAYLOAD_SK)
	{
	  clib_warning ("received SKE payload SK, len %u", plen - 4);
	  last_payload = *payload;
	}
      else
	{
	  clib_warning ("unknown payload %u flags %x length %u", payload,
			skep->flags, plen);
	  if (skep->flags & SKE_PAYLOAD_FLAG_CRITICAL)
	    {
	      sa->unsupported_cp = *payload;
	      return 0;
	    }
	}

      *payload = skep->nextpayload;
      p += plen;
    }

  if (last_payload != SKE_PAYLOAD_SK)
    {
      clib_warning ("Last payload must be SK");
      return 0;
    }

  hmac = vec_new(u8, tr_integ->key_len);
  unsigned int hmac_len = 0;
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;

#if TIME_MEASUREMENT /* time measurement */
  u64 start, end, start_ns, end_ns;
  start = clib_cpu_time_now();
  start_ns = unix_time_now_nsec();
#endif


  ret = Enclave_calc_integr(e_enclave_id, sa->index_spi, 
                            sa->is_initiator,
                            tr_integ->mode, 
                            (u8*) ske, len - tr_integ->key_trunc,
                            hmac, &hmac_len);
   if(ret != SGX_SUCCESS){
      clib_warning("Failed to calc_integr()");
      return 0;
   }
#if DEBUG_SUCCEED
   else
      clib_warning("Succeed to calc_integr()");
#endif

#if TIME_MEASUREMENT /* time measurement */
  end = clib_cpu_time_now();
  end_ns = unix_time_now_nsec();
  clib_warning("(TIME) Elapsed time (len=%d): cycles=%llu, clock=%llu ns", 
                 len - tr_integ->key_trunc, end - start, end_ns - start_ns);
#endif


  plen = plen - sizeof (*skep) - tr_integ->key_trunc;

  if (memcmp (hmac, &skep->payload[plen], tr_integ->key_trunc))
    {
      clib_warning ("message integrity check failed");
      vec_free (hmac);
      return 0;
    }
  vec_free (hmac);

  return ske_decrypt_data (sa, skep->payload, plen);
}

static void
ske_initial_contact_cleanup (ske_sa_t * sa)
{
  ske_main_t *km = &ske_main;
  ske_sa_t *tmp;
  u32 i, *delete = 0;
  ske_child_sa_t *c;
  u32 thread_index = vlib_get_thread_index ();

  if (!sa->initial_contact)
    return;

  /* find old IKE SAs with the same authenticated identity */
  /* *INDENT-OFF* */
  pool_foreach (tmp, km->per_thread_data[thread_index].sas, ({
        if (tmp->i_id.type != sa->i_id.type ||
            vec_len(tmp->i_id.data) != vec_len(sa->i_id.data) ||
            memcmp(sa->i_id.data, tmp->i_id.data, vec_len(sa->i_id.data)))
          continue;

        if (sa->rspi != tmp->rspi)
          vec_add1(delete, tmp - km->per_thread_data[thread_index].sas);
  }));
  /* *INDENT-ON* */

  for (i = 0; i < vec_len (delete); i++)
    {
      tmp =
	pool_elt_at_index (km->per_thread_data[thread_index].sas, delete[i]);
      vec_foreach (c,
		   tmp->childs) ske_delete_tunnel_interface (km->vnet_main,
							       tmp, c);
      ske_delete_sa (tmp);
    }

  vec_free (delete);
  sa->initial_contact = 0;
}

static void
ske_process_auth_req (vlib_main_t * vm, ske_sa_t * sa, ske_header_t * ske)
{
  ske_child_sa_t *first_child_sa;
  int p = 0;
  u32 len = clib_net_to_host_u32 (ske->length);
  u8 payload = ske->nextpayload;
  u8 *plaintext = 0;

  ske_payload_header_t *skep;
  u32 plen;

  clib_warning ("ispi %lx rspi %lx nextpayload %x version %x "
		"exchange %x flags %x msgid %x length %u",
		clib_net_to_host_u64 (ske->ispi),
		clib_net_to_host_u64 (ske->rspi),
		payload, ske->version,
		ske->exchange, ske->flags,
		clib_net_to_host_u32 (ske->msgid), len);

  ske_calc_keys (sa);

  plaintext = ske_decrypt_sk_payload (sa, ske, &payload);

  if (!plaintext)
    {
      if (sa->unsupported_cp)
	ske_set_state (sa, SKE_STATE_NOTIFY_AND_DELETE);
      goto cleanup_and_exit;
    }

  /* select or create 1st child SA */
  if (sa->is_initiator)
    {
      first_child_sa = &sa->childs[0];
    }
  else
    {
      ske_sa_free_all_child_sa (&sa->childs);
      vec_add2 (sa->childs, first_child_sa, 1);
    }


  /* process encrypted payload */
  p = 0;
  while (p < vec_len (plaintext) && payload != SKE_PAYLOAD_NONE)
    {
      skep = (ske_payload_header_t *) & plaintext[p];
      plen = clib_net_to_host_u16 (skep->length);

      if (plen < sizeof (ske_payload_header_t))
	goto cleanup_and_exit;

      if (payload == SKE_PAYLOAD_SA)	/* 33 */
	{
	  clib_warning ("received payload SA, len %u", plen - sizeof (*skep));
	  if (sa->is_initiator)
	    {
	      ske_sa_free_proposal_vector (&first_child_sa->r_proposals);
	      first_child_sa->r_proposals = ske_parse_sa_payload (skep);
	    }
	  else
	    {
	      ske_sa_free_proposal_vector (&first_child_sa->i_proposals);
	      first_child_sa->i_proposals = ske_parse_sa_payload (skep);
	    }
	}
      else if (payload == SKE_PAYLOAD_IDI)	/* 35 */
	{
	  ske_id_payload_header_t *id = (ske_id_payload_header_t *) skep;

	  sa->i_id.type = id->id_type;
	  vec_free (sa->i_id.data);
	  vec_add (sa->i_id.data, id->payload, plen - sizeof (*id));

	  clib_warning ("received payload IDi, len %u id_type %u",
			plen - sizeof (*id), id->id_type);
	}
      else if (payload == SKE_PAYLOAD_IDR)	/* 36 */
	{
	  ske_id_payload_header_t *id = (ske_id_payload_header_t *) skep;

	  sa->r_id.type = id->id_type;
	  vec_free (sa->r_id.data);
	  vec_add (sa->r_id.data, id->payload, plen - sizeof (*id));

	  clib_warning ("received payload IDr len %u id_type %u",
			plen - sizeof (*id), id->id_type);
	}
      else if (payload == SKE_PAYLOAD_AUTH)	/* 39 */
	{
	  ske_auth_payload_header_t *a = (ske_auth_payload_header_t *) skep;

	  if (sa->is_initiator)
	    {
	      sa->r_auth.method = a->auth_method;
	      vec_free (sa->r_auth.data);
	      vec_add (sa->r_auth.data, a->payload, plen - sizeof (*a));
	    }
	  else
	    {
	      sa->i_auth.method = a->auth_method;
	      vec_free (sa->i_auth.data);
	      vec_add (sa->i_auth.data, a->payload, plen - sizeof (*a));
	    }

	  clib_warning ("received payload AUTH, len %u auth_type %u",
			plen - sizeof (*a), a->auth_method);
	}
      else if (payload == SKE_PAYLOAD_NOTIFY)	/* 41 */
	{
	  ske_notify_t *n = ske_parse_notify_payload (skep);
	  if (n->msg_type == SKE_NOTIFY_MSG_INITIAL_CONTACT)
	    {
	      sa->initial_contact = 1;
	    }
	  vec_free (n);
	}
      else if (payload == SKE_PAYLOAD_VENDOR)	/* 43 */
	{
	  ske_parse_vendor_payload (skep);
	}
      else if (payload == SKE_PAYLOAD_TSI)	/* 44 */
	{
	  clib_warning ("received payload TSi, len %u",
			plen - sizeof (*skep));

	  vec_free (first_child_sa->tsi);
	  first_child_sa->tsi = ske_parse_ts_payload (skep);
	}
      else if (payload == SKE_PAYLOAD_TSR)	/* 45 */
	{
	  clib_warning ("received payload TSr, len %u",
			plen - sizeof (*skep));

	  vec_free (first_child_sa->tsr);
	  first_child_sa->tsr = ske_parse_ts_payload (skep);
	}
      else
	{
	  clib_warning ("unknown payload %u flags %x length %u data %u",
			payload, skep->flags, plen - 4,
			format_hex_bytes, skep->payload, plen - 4);

	  if (skep->flags & SKE_PAYLOAD_FLAG_CRITICAL)
	    {
	      ske_set_state (sa, SKE_STATE_NOTIFY_AND_DELETE);
	      sa->unsupported_cp = payload;
	      return;
	    }
	}

      payload = skep->nextpayload;
      p += plen;
    }

cleanup_and_exit:
  vec_free (plaintext);
}

static void
ske_process_informational_req (vlib_main_t * vm, ske_sa_t * sa,
				 ske_header_t * ske)
{
  int p = 0;
  u32 len = clib_net_to_host_u32 (ske->length);
  u8 payload = ske->nextpayload;
  u8 *plaintext = 0;

  ske_payload_header_t *skep;
  u32 plen;

  clib_warning ("ispi %lx rspi %lx nextpayload %x version %x "
		"exchange %x flags %x msgid %x length %u",
		clib_net_to_host_u64 (ske->ispi),
		clib_net_to_host_u64 (ske->rspi),
		payload, ske->version,
		ske->exchange, ske->flags,
		clib_net_to_host_u32 (ske->msgid), len);

  plaintext = ske_decrypt_sk_payload (sa, ske, &payload);

  if (!plaintext)
    goto cleanup_and_exit;

  /* process encrypted payload */
  p = 0;
  while (p < vec_len (plaintext) && payload != SKE_PAYLOAD_NONE)
    {
      skep = (ske_payload_header_t *) & plaintext[p];
      plen = clib_net_to_host_u16 (skep->length);

      if (plen < sizeof (ske_payload_header_t))
	goto cleanup_and_exit;

      if (payload == SKE_PAYLOAD_NOTIFY)	/* 41 */
	{
	  ske_notify_t *n = ske_parse_notify_payload (skep);
	  if (n->msg_type == SKE_NOTIFY_MSG_AUTHENTICATION_FAILED)
	    ske_set_state (sa, SKE_STATE_AUTH_FAILED);
	  vec_free (n);
	}
      else if (payload == SKE_PAYLOAD_DELETE)	/* 42 */
	{
	  sa->del = ske_parse_delete_payload (skep);
	}
      else if (payload == SKE_PAYLOAD_VENDOR)	/* 43 */
	{
	  ske_parse_vendor_payload (skep);
	}
      else
	{
	  clib_warning ("unknown payload %u flags %x length %u data %u",
			payload, skep->flags, plen - 4,
			format_hex_bytes, skep->payload, plen - 4);

	  if (skep->flags & SKE_PAYLOAD_FLAG_CRITICAL)
	    {
	      sa->unsupported_cp = payload;
	      return;
	    }
	}

      payload = skep->nextpayload;
      p += plen;
    }

cleanup_and_exit:
  vec_free (plaintext);
}

static void
ske_process_create_child_sa_req (vlib_main_t * vm, ske_sa_t * sa,
				   ske_header_t * ske)
{
  int p = 0;
  u32 len = clib_net_to_host_u32 (ske->length);
  u8 payload = ske->nextpayload;
  u8 *plaintext = 0;
  u8 rekeying = 0;
  u8 nonce[SKE_NONCE_SIZE];

  ske_payload_header_t *skep;
  u32 plen;
  ske_notify_t *n = 0;
  ske_ts_t *tsi = 0;
  ske_ts_t *tsr = 0;
  ske_sa_proposal_t *proposal = 0;
  ske_child_sa_t *child_sa;

  clib_warning ("ispi %lx rspi %lx nextpayload %x version %x "
		"exchange %x flags %x msgid %x length %u",
		clib_net_to_host_u64 (ske->ispi),
		clib_net_to_host_u64 (ske->rspi),
		payload, ske->version,
		ske->exchange, ske->flags,
		clib_net_to_host_u32 (ske->msgid), len);

  plaintext = ske_decrypt_sk_payload (sa, ske, &payload);

  if (!plaintext)
    goto cleanup_and_exit;

  /* process encrypted payload */
  p = 0;
  while (p < vec_len (plaintext) && payload != SKE_PAYLOAD_NONE)
    {
      skep = (ske_payload_header_t *) & plaintext[p];
      plen = clib_net_to_host_u16 (skep->length);

      if (plen < sizeof (ske_payload_header_t))
	goto cleanup_and_exit;

      else if (payload == SKE_PAYLOAD_SA)
	{
	  proposal = ske_parse_sa_payload (skep);
	}
      else if (payload == SKE_PAYLOAD_NOTIFY)
	{
	  n = ske_parse_notify_payload (skep);
	  if (n->msg_type == SKE_NOTIFY_MSG_REKEY_SA)
	    {
	      rekeying = 1;
	    }
	}
      else if (payload == SKE_PAYLOAD_DELETE)
	{
	  sa->del = ske_parse_delete_payload (skep);
	}
      else if (payload == SKE_PAYLOAD_VENDOR)
	{
	  ske_parse_vendor_payload (skep);
	}
      else if (payload == SKE_PAYLOAD_NONCE)
	{
	  clib_memcpy_fast (nonce, skep->payload, plen - sizeof (*skep));
	}
      else if (payload == SKE_PAYLOAD_TSI)
	{
	  tsi = ske_parse_ts_payload (skep);
	}
      else if (payload == SKE_PAYLOAD_TSR)
	{
	  tsr = ske_parse_ts_payload (skep);
	}
      else
	{
	  clib_warning ("unknown payload %u flags %x length %u data %u",
			payload, skep->flags, plen - 4,
			format_hex_bytes, skep->payload, plen - 4);

	  if (skep->flags & SKE_PAYLOAD_FLAG_CRITICAL)
	    {
	      sa->unsupported_cp = payload;
	      return;
	    }
	}

      payload = skep->nextpayload;
      p += plen;
    }

  if (sa->is_initiator && proposal->protocol_id == SKE_PROTOCOL_ESP)
    {
      ske_rekey_t *rekey = &sa->rekey[0];
      rekey->protocol_id = proposal->protocol_id;
      rekey->i_proposal =
	ske_select_proposal (proposal, SKE_PROTOCOL_ESP);
      rekey->i_proposal->spi = rekey->spi;
      rekey->r_proposal = proposal;
      rekey->tsi = tsi;
      rekey->tsr = tsr;
      /* update Nr */
      vec_free (sa->r_nonce);
      vec_add (sa->r_nonce, nonce, SKE_NONCE_SIZE);
      child_sa = ske_sa_get_child (sa, rekey->ispi, SKE_PROTOCOL_ESP, 1);
      if (child_sa)
	{
	  child_sa->rekey_retries = 0;
	}
    }
  else if (rekeying)
    {
      ske_rekey_t *rekey;
      child_sa = ske_sa_get_child (sa, n->spi, n->protocol_id, 1);
      if (!child_sa)
	{
	  clib_warning ("child SA spi %lx not found", n->spi);
	  goto cleanup_and_exit;
	}
      vec_add2 (sa->rekey, rekey, 1);
      rekey->protocol_id = n->protocol_id;
      rekey->spi = n->spi;
      rekey->i_proposal = proposal;
      rekey->r_proposal =
	ske_select_proposal (proposal, SKE_PROTOCOL_ESP);
      rekey->tsi = tsi;
      rekey->tsr = tsr;
      /* update Ni */
      vec_free (sa->i_nonce);
      vec_add (sa->i_nonce, nonce, SKE_NONCE_SIZE);
      /* generate new Nr */
      vec_free (sa->r_nonce);
      sa->r_nonce = vec_new (u8, SKE_NONCE_SIZE);
      RAND_bytes ((u8 *) sa->r_nonce, SKE_NONCE_SIZE);
    }

cleanup_and_exit:
  vec_free (plaintext);
  vec_free (n);
}

static u8 *
ske_sa_generate_authmsg (ske_sa_t * sa, int is_responder)
{
  u8 *authmsg = 0;
  u8 *data;
  u8 *nonce;
  ske_id_t *id;
  u8 *packet_data;
  ske_sa_transform_t *tr_prf;

  tr_prf =
    ske_sa_get_td_for_type (sa->r_proposals, SKE_TRANSFORM_TYPE_PRF);

  if (is_responder)
    {
      id = &sa->r_id;
      nonce = sa->i_nonce;
      packet_data = sa->last_sa_init_res_packet_data;
    }
  else
    {
      id = &sa->i_id;
      nonce = sa->r_nonce;
      packet_data = sa->last_sa_init_req_packet_data;
    }

  data = vec_new (u8, 4);
  data[0] = id->type;
  vec_append (data, id->data);

  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  u8 *id_hash = vec_new(u8, tr_prf->key_trunc);
  u32 out_len = 0;
#if TIME_MEASUREMENT /* time measurement */
  u64 start, end, start_ns, end_ns;
  start = clib_cpu_time_now();
  start_ns = unix_time_now_nsec();
#endif


  ret = Enclave_calc_prf(e_enclave_id, 
                        sa->index_spi, TYPE_AUTHMSG,  tr_prf->mode, 
                        is_responder,
                        tr_prf->key_trunc, data, vec_len(data), id_hash, &out_len);
  if(ret != SGX_SUCCESS){
    clib_warning("Failed to calc_prf(AUTHMSG)");
  }
#if DEBUG_SUCCEED
  else
    clib_warning("Succeed to calc_prf(AUTHMSG)");
#endif

#if TIME_MEASUREMENT /* time measurement */
  end = clib_cpu_time_now();
  end_ns = unix_time_now_nsec();
  clib_warning("(TIME) Elapsed time: cycles=%llu, clock=%llu ns", 
                 end - start, end_ns - start_ns);
#endif


  vec_append (authmsg, packet_data);
  vec_append (authmsg, nonce);
  vec_append (authmsg, id_hash);
  vec_free (id_hash);
  vec_free (data);

  return authmsg;
}

static int
ske_ts_cmp (ske_ts_t * ts1, ske_ts_t * ts2)
{
  if (ts1->ts_type == ts2->ts_type && ts1->protocol_id == ts2->protocol_id &&
      ts1->start_port == ts2->start_port && ts1->end_port == ts2->end_port &&
      ts1->start_addr.as_u32 == ts2->start_addr.as_u32 &&
      ts1->end_addr.as_u32 == ts2->end_addr.as_u32)
    return 1;

  return 0;
}

static void
ske_sa_match_ts (ske_sa_t * sa)
{
  ske_main_t *km = &ske_main;
  ske_profile_t *p;
  ske_ts_t *ts, *p_tsi, *p_tsr, *tsi = 0, *tsr = 0;
  ske_id_t *id;

  /* *INDENT-OFF* */
  pool_foreach (p, km->profiles, ({

    if (sa->is_initiator)
      {
        p_tsi = &p->loc_ts;
        p_tsr = &p->rem_ts;
        id = &sa->r_id;
      }
    else
      {
        p_tsi = &p->rem_ts;
        p_tsr = &p->loc_ts;
        id = &sa->i_id;
      }

    /* check id */
    if (p->rem_id.type != id->type ||
        vec_len(p->rem_id.data) != vec_len(id->data) ||
        memcmp(p->rem_id.data, id->data, vec_len(p->rem_id.data)))
      continue;

    vec_foreach(ts, sa->childs[0].tsi)
      {
        if (ske_ts_cmp(p_tsi, ts))
          {
            tsi = vec_dup(ts);
            break;
          }
      }

    vec_foreach(ts, sa->childs[0].tsr)
      {
        if (ske_ts_cmp(p_tsr, ts))
          {
            tsr = vec_dup(ts);
            break;
          }
      }

    break;
  }));
  /* *INDENT-ON* */

  if (tsi && tsr)
    {
      vec_free (sa->childs[0].tsi);
      vec_free (sa->childs[0].tsr);
      sa->childs[0].tsi = tsi;
      sa->childs[0].tsr = tsr;
    }
  else
    {
      vec_free (tsi);
      vec_free (tsr);
      ske_set_state (sa, SKE_STATE_TS_UNACCEPTABLE);
    }
}

static void
ske_sa_auth (ske_sa_t * sa)
{
  ske_main_t *km = &ske_main;
  ske_profile_t *p, *sel_p = 0;
  u8 *authmsg, *key_pad, *psk = 0, *auth = 0;
  ske_sa_transform_t *tr_prf;

  tr_prf =
    ske_sa_get_td_for_type (sa->r_proposals, SKE_TRANSFORM_TYPE_PRF);

  /* only shared key and rsa signature */
  if (!(sa->i_auth.method == SKE_AUTH_METHOD_SHARED_KEY_MIC ||
	sa->i_auth.method == SKE_AUTH_METHOD_RSA_SIG))
    {
      clib_warning ("unsupported authentication method %u",
		    sa->i_auth.method);
      ske_set_state (sa, SKE_STATE_AUTH_FAILED);
      return;
    }

  key_pad = format (0, "%s", SKE_KEY_PAD);
  authmsg = ske_sa_generate_authmsg (sa, sa->is_initiator);

  ske_id_t *sa_id;
  ske_auth_t *sa_auth;

  if (sa->is_initiator)
    {
      sa_id = &sa->r_id;
      sa_auth = &sa->r_auth;
    }
  else
    {
      sa_id = &sa->i_id;
      sa_auth = &sa->i_auth;
    }

  /* *INDENT-OFF* */
  pool_foreach (p, km->profiles, ({

    /* check id */
    if (p->rem_id.type != sa_id->type ||
        vec_len(p->rem_id.data) != vec_len(sa_id->data) ||
        memcmp(p->rem_id.data, sa_id->data, vec_len(p->rem_id.data)))
      continue;

    if (sa_auth->method == SKE_AUTH_METHOD_SHARED_KEY_MIC)
      {
        if (!p->auth.data ||
             p->auth.method != SKE_AUTH_METHOD_SHARED_KEY_MIC)
          continue;

        sgx_status_t ret = SGX_ERROR_UNEXPECTED;
        auth = vec_new(u8, tr_prf->key_trunc);
        u32 auth_len = 0;
#if TIME_MEASUREMENT /* time measurement */
  u64 start, end, start_ns, end_ns;
  start = clib_cpu_time_now();
  start_ns = unix_time_now_nsec();
#endif


        ret = Enclave_calc_prf(e_enclave_id, 
                        sa->index_spi, TYPE_AUTH1,  tr_prf->mode, 
                        sa->is_initiator,
                        tr_prf->key_trunc, authmsg, vec_len(authmsg), auth, &auth_len);
        if(ret != SGX_SUCCESS){
            clib_warning("Failed to calc_prf(AUTH1)");
        }
#if DEBUG_SUCCEED
        else
            clib_warning("Succeed to calc_prf(AUTH1)");
#endif

#if TIME_MEASUREMENT /* time measurement */
  end = clib_cpu_time_now();
  end_ns = unix_time_now_nsec();
  clib_warning("(TIME) Elapsed time: cycles=%llu, clock=%llu ns", 
                 end - start, end_ns - start_ns);
#endif


        if (!memcmp(auth, sa_auth->data, vec_len(sa_auth->data)))
          {
            ske_set_state(sa, SKE_STATE_AUTHENTICATED);
            vec_free(auth);
            sel_p = p;
            break;
          }

      }
    else if (sa_auth->method == SKE_AUTH_METHOD_RSA_SIG)
      {
        if (p->auth.method != SKE_AUTH_METHOD_RSA_SIG)
          continue;

        if (ske_verify_sign(p->auth.key, sa_auth->data, authmsg) == 1)
          {
            ske_set_state(sa, SKE_STATE_AUTHENTICATED);
            sel_p = p;
            break;
          }
      }

    vec_free(auth);
    vec_free(psk);
  }));
  /* *INDENT-ON* */

  vec_free (authmsg);

  if (sa->state == SKE_STATE_AUTHENTICATED)
    {
      if (!sa->is_initiator)
	{
	  vec_free (sa->r_id.data);
	  sa->r_id.data = vec_dup (sel_p->loc_id.data);
	  sa->r_id.type = sel_p->loc_id.type;

	  /* generate our auth data */
	  authmsg = ske_sa_generate_authmsg (sa, 1);
	  if (sel_p->auth.method == SKE_AUTH_METHOD_SHARED_KEY_MIC)
	    {
              sa->r_auth.data = vec_new(u8, tr_prf->key_trunc);
              sgx_status_t ret = SGX_ERROR_UNEXPECTED;
              u32 auth_len = 0;
#if TIME_MEASUREMENT /* time measurement */
  u64 start, end, start_ns, end_ns;
  start = clib_cpu_time_now();
  start_ns = unix_time_now_nsec();
#endif


              ret = Enclave_calc_prf(e_enclave_id, 
                        sa->index_spi, TYPE_AUTH2,  tr_prf->mode, 
                        sa->is_initiator,
                        tr_prf->key_trunc, authmsg, vec_len(authmsg), sa->r_auth.data, &auth_len);
              if(ret != SGX_SUCCESS){
                  clib_warning("Failed to calc_prf(AUTH1)");
              }
#if DEBUG_SUCCEED
              else
                  clib_warning("Succeed to calc_prf(AUTH1)");
#endif

#if TIME_MEASUREMENT /* time measurement */
  end = clib_cpu_time_now();
  end_ns = unix_time_now_nsec();
  clib_warning("(TIME) Elapsed time: cycles=%llu, clock=%llu ns", 
                 end - start, end_ns - start_ns);
#endif


	      sa->r_auth.method = SKE_AUTH_METHOD_SHARED_KEY_MIC;
	    }
	  else if (sel_p->auth.method == SKE_AUTH_METHOD_RSA_SIG)
	    {
	      sa->r_auth.data = ske_calc_sign (km->pkey, authmsg);
	      sa->r_auth.method = SKE_AUTH_METHOD_RSA_SIG;
	    }
	  vec_free (authmsg);

	  /* select transforms for 1st child sa */
	  ske_sa_free_proposal_vector (&sa->childs[0].r_proposals);
	  sa->childs[0].r_proposals =
	    ske_select_proposal (sa->childs[0].i_proposals,
				   SKE_PROTOCOL_ESP);
	}
    }
  else
    {
      ske_set_state (sa, SKE_STATE_AUTH_FAILED);
    }
  vec_free (psk);
  vec_free (key_pad);
}


static void
ske_sa_auth_init (ske_sa_t * sa)
{
  ske_main_t *km = &ske_main;
  u8 *authmsg, *key_pad, *psk = 0, *auth = 0;
  ske_sa_transform_t *tr_prf;

  tr_prf =
    ske_sa_get_td_for_type (sa->r_proposals, SKE_TRANSFORM_TYPE_PRF);

  /* only shared key and rsa signature */
  if (!(sa->i_auth.method == SKE_AUTH_METHOD_SHARED_KEY_MIC ||
	sa->i_auth.method == SKE_AUTH_METHOD_RSA_SIG))
    {
      clib_warning ("unsupported authentication method %u",
		    sa->i_auth.method);
      ske_set_state (sa, SKE_STATE_AUTH_FAILED);
      return;
    }

  key_pad = format (0, "%s", SKE_KEY_PAD);
  authmsg = ske_sa_generate_authmsg (sa, 0);
  psk = ske_calc_prf (tr_prf, sa->i_auth.data, key_pad);
  auth = ske_calc_prf (tr_prf, psk, authmsg);


  if (sa->i_auth.method == SKE_AUTH_METHOD_SHARED_KEY_MIC)
    {
      sa->i_auth.data = ske_calc_prf (tr_prf, psk, authmsg);
      sa->i_auth.method = SKE_AUTH_METHOD_SHARED_KEY_MIC;
    }
  else if (sa->i_auth.method == SKE_AUTH_METHOD_RSA_SIG)
    {
      sa->i_auth.data = ske_calc_sign (km->pkey, authmsg);
      sa->i_auth.method = SKE_AUTH_METHOD_RSA_SIG;
    }

  vec_free (psk);
  vec_free (key_pad);
  vec_free (auth);
  vec_free (authmsg);
}

static int
ske_create_tunnel_interface (vnet_main_t * vnm, ske_sa_t * sa,
			       ske_child_sa_t * child)
{
  ske_main_t *km = &ske_main;
  ske_profile_t *p = 0;
  ipsec_add_del_tunnel_args_t a;
  ske_sa_transform_t *tr;
  ske_sa_proposal_t *proposals;
  u8 encr_type = 0;
  u8 integ_type = 0;
  u8 is_aead = 0;

  if (!child->r_proposals)
    {
      ske_set_state (sa, SKE_STATE_NO_PROPOSAL_CHOSEN);
      return 1;
    }

  clib_memset(&a, 0, sizeof(a));
  a.is_add = 1;

  if (sa->is_initiator)
    {
      a.local_ip.ip4.as_u32 = sa->iaddr.as_u32;
      a.remote_ip.ip4.as_u32 = sa->raddr.as_u32;
      proposals = child->i_proposals;
      a.local_spi = child->r_proposals[0].spi;
      a.remote_spi = child->i_proposals[0].spi;
    }
  else
    {
      a.local_ip.ip4.as_u32 = sa->raddr.as_u32;
      a.remote_ip.ip4.as_u32 = sa->iaddr.as_u32;
      proposals = child->r_proposals;
      a.local_spi = child->i_proposals[0].spi;
      a.remote_spi = child->r_proposals[0].spi;
    }

  a.anti_replay = 1;

  tr = ske_sa_get_td_for_type (proposals, SKE_TRANSFORM_TYPE_ESN);
  if(tr)
    a.esn = tr->esn_type;
  else
    a.esn = 0;

  tr = ske_sa_get_td_for_type (proposals, SKE_TRANSFORM_TYPE_ENCR);
  if (tr)
    {
      if (tr->encr_type == SKE_TRANSFORM_ENCR_TYPE_AES_CBC && tr->key_len)
	{
	  switch (tr->key_len)
	    {
	    case 16:
	      encr_type = IPSEC_CRYPTO_ALG_AES_CBC_128;
	      break;
	    case 24:
	      encr_type = IPSEC_CRYPTO_ALG_AES_CBC_192;
	      break;
	    case 32:
	      encr_type = IPSEC_CRYPTO_ALG_AES_CBC_256;
	      break;
	    default:
	      ske_set_state (sa, SKE_STATE_NO_PROPOSAL_CHOSEN);
	      return 1;
	      break;
	    }
	}
      else if (tr->encr_type == SKE_TRANSFORM_ENCR_TYPE_AES_GCM_16
               && tr->key_len)
        {
          switch (tr->key_len)
            {
            case 16:
              encr_type = IPSEC_CRYPTO_ALG_AES_GCM_128;
              break;
            case 24:
              encr_type = IPSEC_CRYPTO_ALG_AES_GCM_192;
              break;
            case 32:
              encr_type = IPSEC_CRYPTO_ALG_AES_GCM_256;
              break;
            default:
              ske_set_state (sa, SKE_STATE_NO_PROPOSAL_CHOSEN);
              return 1;
              break;
            }
          is_aead = 1;
        }
      else
	{
	  ske_set_state (sa, SKE_STATE_NO_PROPOSAL_CHOSEN);
	  return 1;
	}
    }
  else
    {
      ske_set_state (sa, SKE_STATE_NO_PROPOSAL_CHOSEN);
      return 1;
    }

  if(!is_aead)
  {
    tr = ske_sa_get_td_for_type (proposals, SKE_TRANSFORM_TYPE_INTEG);
    if (tr)
      {
        switch (tr->integ_type)
	  {
 	  case SKE_TRANSFORM_INTEG_TYPE_AUTH_HMAC_SHA2_256_128:
	    integ_type = IPSEC_INTEG_ALG_SHA_256_128;
	    break;
	  case SKE_TRANSFORM_INTEG_TYPE_AUTH_HMAC_SHA2_384_192:
	    integ_type = IPSEC_INTEG_ALG_SHA_384_192;
	    break;
	  case SKE_TRANSFORM_INTEG_TYPE_AUTH_HMAC_SHA2_512_256:
	    integ_type = IPSEC_INTEG_ALG_SHA_512_256;
	    break;
	  case SKE_TRANSFORM_INTEG_TYPE_AUTH_HMAC_SHA1_96:
	    integ_type = IPSEC_INTEG_ALG_SHA1_96;
	    break;
	  default:
	    ske_set_state (sa, SKE_STATE_NO_PROPOSAL_CHOSEN);
	    return 1;
	  }
      }
    else
      {
        ske_set_state(sa, SKE_STATE_NO_PROPOSAL_CHOSEN);
        return 1;
      }
    }
  else
   {
      integ_type = IPSEC_INTEG_ALG_NONE;
   }

  ske_calc_child_keys (sa, child);
  u8 *loc_ckey, *rem_ckey, *loc_ikey, *rem_ikey;
  u32 salt_local = 0, salt_remote = 0;

  if (sa->is_initiator)
    {
      loc_ikey = child->sk_ai;
      rem_ikey = child->sk_ar;
      loc_ckey = child->sk_ei;
      rem_ckey = child->sk_er;
  
      if(is_aead)
        {
           salt_remote = child->salt_er;
           salt_local = child->salt_ei;
        }
    }
  else
    {
      loc_ikey = child->sk_ar;
      rem_ikey = child->sk_ai;
      loc_ckey = child->sk_er;
      rem_ckey = child->sk_ei;
  
      if(is_aead)
        {
           salt_remote = child->salt_ei;
           salt_local = child->salt_er;
        }

    }

  a.integ_alg = integ_type;
  a.local_integ_key_len = vec_len(loc_ikey);
  clib_memcpy_fast(a.local_integ_key, loc_ikey, a.local_integ_key_len);
  a.remote_integ_key_len = vec_len(rem_ikey);
  clib_memcpy_fast(a.remote_integ_key, rem_ikey, a.remote_integ_key_len);

  a.crypto_alg = encr_type;
  a.local_crypto_key_len = vec_len(loc_ckey);
  clib_memcpy_fast(a.local_crypto_key, loc_ckey, a.local_crypto_key_len);
  a.remote_crypto_key_len = vec_len(rem_ckey);
  clib_memcpy_fast(a.remote_crypto_key, rem_ckey, a.remote_crypto_key_len);

  if(is_aead)
    {
      a.salt_local = salt_local;
      a.salt_remote = salt_remote;
    }

  if(sa->is_profile_index_set)
    p = pool_elt_at_index(km->profiles, sa->profile_index);

  if (p && p->lifetime)
    {
      child->time_to_expiration = 
        vlib_time_now (vnm->vlib_main) + p->lifetime;
      if (p->lifetime_jitter)
	{
	  // This is not much better than rand(3), which Coverity warns
	  // is unsuitable for security applications; random_u32 is
	  // however fast. If this perturbance to the expiration time
	  // needs to use a better RNG then we may need to use something
	  // like /dev/urandom which has significant overhead.
	  u32 rnd = (u32) (vlib_time_now (vnm->vlib_main) * 1e6);
	  rnd = random_u32 (&rnd);

	  child->time_to_expiration += 1 + (rnd % p->lifetime_jitter);
	}
    }

#if CLEAR_AND_SEAL /* call to seal the crypto context */
   sgx_status_t ret = SGX_ERROR_UNEXPECTED;
   v8* sealed_data = 0;
   sealed_data = vec_new(u8, 2048);
   unsigned int sealed_len = 0;
 
#if TIME_MEASUREMENT /* time measurement */
  u64 start, end, start_ns, end_ns;
  start = clib_cpu_time_now();
  start_ns = unix_time_now_nsec();
#endif

     
   ret = Enclave_seal_crypto_context(e_enclave_id, sa->is_initiator, 
                sa->index_spi, sealed_data, &sealed_len); 
   if(ret != SGX_SUCCESS){
     clib_warning("Failed to seal_crypto_context()");
   }

#if DEBUG_SUCCEED
   else 
     clib_warning("Succeed to seal_crypto_context(sealed_len=%d)", sealed_len);
#endif

#if TIME_MEASUREMENT /* time measurement */
  end = clib_cpu_time_now();
  end_ns = unix_time_now_nsec();
  clib_warning("(TIME) Elapsed time: cycles=%llu, clock=%llu ns", 
                 end - start, end_ns - start_ns);
#endif


#endif

  ipsec_add_del_tunnel_if(&a);

  return 0;
}

static int
ske_delete_tunnel_interface (vnet_main_t * vnm, ske_sa_t * sa,
			       ske_child_sa_t * child)
{
  ipsec_add_del_tunnel_args_t a;

  if(sa->is_initiator)
    {
      if(!vec_len(child->i_proposals))
      return 0;

      a.is_add = 0;
      a.local_ip.ip4.as_u32 = sa->iaddr.as_u32;
      a.remote_ip.ip4.as_u32 = sa->raddr.as_u32;
      a.local_spi = child->r_proposals[0].spi;
      a.remote_spi = child->i_proposals[0].spi;
    }
  else
    {
      if(!vec_len(child->r_proposals))
      return 0;

      a.is_add = 0;
      a.local_ip.ip4.as_u32 = sa->raddr.as_u32;
      a.remote_ip.ip4.as_u32 = sa->iaddr.as_u32;
      a.local_spi = child->i_proposals[0].spi;
      a.remote_spi = child->r_proposals[0].spi;
    }

  ipsec_add_del_tunnel_if(&a);

  return 0;
}

static u32
ske_generate_message (ske_sa_t * sa, ske_header_t * ske, void *user)
{
  v8 *integ = 0;
  ske_payload_header_t *ph;
  u16 plen;
  u32 tlen = 0;

  ske_sa_transform_t *tr_encr, *tr_integ;
  tr_encr =
    ske_sa_get_td_for_type (sa->r_proposals, SKE_TRANSFORM_TYPE_ENCR);
  tr_integ =
    ske_sa_get_td_for_type (sa->r_proposals, SKE_TRANSFORM_TYPE_INTEG);

  ske_payload_chain_t *chain = 0;
  ske_payload_new_chain (chain);

  if (ske->exchange == SKE_EXCHANGE_SA_INIT)
    {
      if (sa->r_proposals == 0)
	{
	  ske_payload_add_notify (chain,
				    SKE_NOTIFY_MSG_NO_PROPOSAL_CHOSEN, 0);
	  ske_set_state (sa, SKE_STATE_NOTIFY_AND_DELETE);
	}
      else if (sa->dh_group == SKE_TRANSFORM_DH_TYPE_NONE)
	{
	  u8 *data = vec_new (u8, 2);
	  ske_sa_transform_t *tr_dh;
	  tr_dh =
	    ske_sa_get_td_for_type (sa->r_proposals,
				      SKE_TRANSFORM_TYPE_DH);
	  ASSERT (tr_dh && tr_dh->dh_type);

	  data[0] = (tr_dh->dh_type >> 8) & 0xff;
	  data[1] = (tr_dh->dh_type) & 0xff;

	  ske_payload_add_notify (chain,
				    SKE_NOTIFY_MSG_INVALID_KE_PAYLOAD,
				    data);
	  vec_free (data);
	  ske_set_state (sa, SKE_STATE_NOTIFY_AND_DELETE);
	}
      else if (sa->state == SKE_STATE_NOTIFY_AND_DELETE)
	{
	  u8 *data = vec_new (u8, 1);

	  data[0] = sa->unsupported_cp;
	  ske_payload_add_notify (chain,
				    SKE_NOTIFY_MSG_UNSUPPORTED_CRITICAL_PAYLOAD,
				    data);
	  vec_free (data);
	}
      else
	{
	  ske->rspi = clib_host_to_net_u64 (sa->rspi);
	  ske_payload_add_sa (chain, sa->r_proposals);
	  ske_payload_add_ke (chain, sa->dh_group, sa->r_dh_data);
	  ske_payload_add_nonce (chain, sa->r_nonce);
	}
    }
  else if (ske->exchange == SKE_EXCHANGE_IKE_AUTH)
    {
      if (sa->state == SKE_STATE_AUTHENTICATED)
	{
	  ske_payload_add_id (chain, &sa->r_id, SKE_PAYLOAD_IDR);
	  ske_payload_add_auth (chain, &sa->r_auth);
	  ske_payload_add_sa (chain, sa->childs[0].r_proposals);
	  ske_payload_add_ts (chain, sa->childs[0].tsi, SKE_PAYLOAD_TSI);
	  ske_payload_add_ts (chain, sa->childs[0].tsr, SKE_PAYLOAD_TSR);
	}
      else if (sa->state == SKE_STATE_AUTH_FAILED)
	{
	  ske_payload_add_notify (chain,
				    SKE_NOTIFY_MSG_AUTHENTICATION_FAILED,
				    0);
	  ske_set_state (sa, SKE_STATE_NOTIFY_AND_DELETE);
	}
      else if (sa->state == SKE_STATE_TS_UNACCEPTABLE)
	{
	  ske_payload_add_notify (chain, SKE_NOTIFY_MSG_TS_UNACCEPTABLE,
				    0);
	  ske_payload_add_id (chain, &sa->r_id, SKE_PAYLOAD_IDR);
	  ske_payload_add_auth (chain, &sa->r_auth);
	}
      else if (sa->state == SKE_STATE_NO_PROPOSAL_CHOSEN)
	{
	  ske_payload_add_notify (chain,
				    SKE_NOTIFY_MSG_NO_PROPOSAL_CHOSEN, 0);
	  ske_payload_add_id (chain, &sa->r_id, SKE_PAYLOAD_IDR);
	  ske_payload_add_auth (chain, &sa->r_auth);
	  ske_payload_add_ts (chain, sa->childs[0].tsi, SKE_PAYLOAD_TSI);
	  ske_payload_add_ts (chain, sa->childs[0].tsr, SKE_PAYLOAD_TSR);
	}
      else if (sa->state == SKE_STATE_NOTIFY_AND_DELETE)
	{
	  u8 *data = vec_new (u8, 1);

	  data[0] = sa->unsupported_cp;
	  ske_payload_add_notify (chain,
				    SKE_NOTIFY_MSG_UNSUPPORTED_CRITICAL_PAYLOAD,
				    data);
	  vec_free (data);
	}
      else if (sa->state == SKE_STATE_SA_INIT)
	{
	  ske_payload_add_id (chain, &sa->i_id, SKE_PAYLOAD_IDI);
	  ske_payload_add_auth (chain, &sa->i_auth);
	  ske_payload_add_sa (chain, sa->childs[0].i_proposals);
	  ske_payload_add_ts (chain, sa->childs[0].tsi, SKE_PAYLOAD_TSI);
	  ske_payload_add_ts (chain, sa->childs[0].tsr, SKE_PAYLOAD_TSR);
	}
      else
	{
	  ske_set_state (sa, SKE_STATE_DELETED);
	  goto done;
	}
    }
  else if (ske->exchange == SKE_EXCHANGE_INFORMATIONAL)
    {
      /* if pending delete */
      if (sa->del)
	{
	  if (sa->del[0].protocol_id == SKE_PROTOCOL_IKE)
	    {
	      if (sa->is_initiator)
		ske_payload_add_delete (chain, sa->del);

	      /* The response to a request that deletes the IKE SA is an empty
	         INFORMATIONAL response. */
	      ske_set_state (sa, SKE_STATE_NOTIFY_AND_DELETE);
	    }
	  /* The response to a request that deletes ESP or AH SAs will contain
	     delete payloads for the paired SAs going in the other direction. */
	  else
	    {
	      ske_payload_add_delete (chain, sa->del);
	    }
	  vec_free (sa->del);
	  sa->del = 0;
	}
      /* received N(AUTHENTICATION_FAILED) */
      else if (sa->state == SKE_STATE_AUTH_FAILED)
	{
	  ske_set_state (sa, SKE_STATE_DELETED);
	  goto done;
	}
      /* received unsupported critical payload */
      else if (sa->unsupported_cp)
	{
	  u8 *data = vec_new (u8, 1);

	  data[0] = sa->unsupported_cp;
	  ske_payload_add_notify (chain,
				    SKE_NOTIFY_MSG_UNSUPPORTED_CRITICAL_PAYLOAD,
				    data);
	  vec_free (data);
	  sa->unsupported_cp = 0;
	}
      /* else send empty response */
    }
  else if (ske->exchange == SKE_EXCHANGE_CREATE_CHILD_SA)
    {
      if (sa->is_initiator)
	{

	  ske_sa_proposal_t *proposals = (ske_sa_proposal_t *) user;
	  ske_notify_t notify;
	  u8 *data = vec_new (u8, 4);
	  clib_memset (&notify, 0, sizeof (notify));
	  notify.protocol_id = SKE_PROTOCOL_ESP;
	  notify.spi = sa->childs[0].i_proposals->spi;
	  *(u32 *) data = clib_host_to_net_u32 (notify.spi);

	  ske_payload_add_sa (chain, proposals);
	  ske_payload_add_nonce (chain, sa->i_nonce);
	  ske_payload_add_ts (chain, sa->childs[0].tsi, SKE_PAYLOAD_TSI);
	  ske_payload_add_ts (chain, sa->childs[0].tsr, SKE_PAYLOAD_TSR);
	  ske_payload_add_notify_2 (chain, SKE_NOTIFY_MSG_REKEY_SA, data,
				      &notify);

	  vec_free (data);
	}
      else
	{
	  if (sa->rekey)
	    {
	      ske_payload_add_sa (chain, sa->rekey[0].r_proposal);
	      ske_payload_add_nonce (chain, sa->r_nonce);
	      ske_payload_add_ts (chain, sa->rekey[0].tsi,
				    SKE_PAYLOAD_TSI);
	      ske_payload_add_ts (chain, sa->rekey[0].tsr,
				    SKE_PAYLOAD_TSR);
	      vec_del1 (sa->rekey, 0);
	    }
	  else if (sa->unsupported_cp)
	    {
	      u8 *data = vec_new (u8, 1);

	      data[0] = sa->unsupported_cp;
	      ske_payload_add_notify (chain,
					SKE_NOTIFY_MSG_UNSUPPORTED_CRITICAL_PAYLOAD,
					data);
	      vec_free (data);
	      sa->unsupported_cp = 0;
	    }
	  else
	    {
	      ske_payload_add_notify (chain,
					SKE_NOTIFY_MSG_NO_ADDITIONAL_SAS,
					0);
	    }
	}
    }

  /* SKE header */
  ske->version = IKE_VERSION_2;
  ske->nextpayload = SKE_PAYLOAD_SK;
  tlen = sizeof (*ske);
  if (sa->is_initiator)
    {
      ske->flags = SKE_HDR_FLAG_INITIATOR;
      sa->last_init_msg_id = clib_net_to_host_u32 (ske->msgid);
    }
  else
    {
      ske->flags = SKE_HDR_FLAG_RESPONSE;
    }


  if (ske->exchange == SKE_EXCHANGE_SA_INIT)
    {
      tlen += vec_len (chain->data);
      ske->nextpayload = chain->first_payload_type;
      ske->length = clib_host_to_net_u32 (tlen);
      clib_memcpy_fast (ske->payload, chain->data, vec_len (chain->data));

      /* store whole IKE payload - needed for PSK auth */
      vec_free (sa->last_sa_init_res_packet_data);
      vec_add (sa->last_sa_init_res_packet_data, ske, tlen);
    }
  else
    {

      ske_payload_chain_add_padding (chain, tr_encr->block_size);

      /* SK payload */
      plen = sizeof (*ph);
      ph = (ske_payload_header_t *) & ske->payload[0];
      ph->nextpayload = chain->first_payload_type;
      ph->flags = 0;
      int enc_len = ske_encrypt_data (sa, chain->data, ph->payload);
      plen += enc_len;

      /* add space for hmac */
      plen += tr_integ->key_trunc;
      tlen += plen;

      /* payload and total length */
      ph->length = clib_host_to_net_u16 (plen);
      ske->length = clib_host_to_net_u32 (tlen);

      /* calc integrity data for whole packet except hash itself */
      integ = vec_new(u8, tr_integ->key_len);
      unsigned int integ_len = 0;
      sgx_status_t ret = SGX_ERROR_UNEXPECTED;
#if TIME_MEASUREMENT /* time measurement */
  u64 start, end, start_ns, end_ns;
  start = clib_cpu_time_now();
  start_ns = unix_time_now_nsec();
#endif


      ret = Enclave_calc_integr(e_enclave_id, sa->index_spi, 
                            !sa->is_initiator,
                            tr_integ->mode, 
                            (u8*) ske, tlen - tr_integ->key_trunc,
                            integ, &integ_len);
      if(ret != SGX_SUCCESS){
          clib_warning("Failed to calc_integr()");
      }
#if DEBUG_SUCCEED
      else 
          clib_warning("Succeed to calc_integr(integ_len=%d)", integ_len);
#endif

#if TIME_MEASUREMENT /* time measurement */
  end = clib_cpu_time_now();
  end_ns = unix_time_now_nsec();
  clib_warning("(TIME) Elapsed time (len=%d) : cycles=%llu, clock=%llu ns", 
                 tlen - tr_integ->key_trunc, end - start, end_ns - start_ns);
#endif


      clib_memcpy_fast (ske->payload + tlen - tr_integ->key_trunc -
			sizeof (*ske), integ, tr_integ->key_trunc);

      /* store whole IKE payload - needed for retransmit */
      vec_free (sa->last_res_packet_data);
      vec_add (sa->last_res_packet_data, ske, tlen);
    }

done:
  ske_payload_destroy_chain (chain);
  vec_free (integ);
  return tlen;
}

static int
ske_retransmit_sa_init (ske_header_t * ske,
			  ip4_address_t iaddr, ip4_address_t raddr)
{
  ske_main_t *km = &ske_main;
  ske_sa_t *sa;
  u32 thread_index = vlib_get_thread_index ();

  /* *INDENT-OFF* */
  pool_foreach (sa, km->per_thread_data[thread_index].sas, ({
    if (sa->ispi == clib_net_to_host_u64(ske->ispi) &&
        sa->iaddr.as_u32 == iaddr.as_u32 &&
        sa->raddr.as_u32 == raddr.as_u32)
      {
        int p = 0;
        u32 len = clib_net_to_host_u32(ske->length);
        u8 payload = ske->nextpayload;

        while (p < len && payload!= SKE_PAYLOAD_NONE) {
          ske_payload_header_t * skep = (ske_payload_header_t *) &ske->payload[p];
          u32 plen = clib_net_to_host_u16(skep->length);

          if (plen < sizeof(ske_payload_header_t))
            return -1;

          if (payload == SKE_PAYLOAD_NONCE)
            {
              if (!memcmp(sa->i_nonce, skep->payload, plen - sizeof(*skep)))
                {
                  /* req is retransmit */
                  if (sa->state == SKE_STATE_SA_INIT)
                    {
                      ske_header_t * tmp;
                      tmp = (ske_header_t*)sa->last_sa_init_res_packet_data;
                      ske->ispi = tmp->ispi;
                      ske->rspi = tmp->rspi;
                      ske->nextpayload = tmp->nextpayload;
                      ske->version = tmp->version;
                      ske->exchange = tmp->exchange;
                      ske->flags = tmp->flags;
                      ske->msgid = tmp->msgid;
                      ske->length = tmp->length;
                      clib_memcpy_fast(ske->payload, tmp->payload,
                             clib_net_to_host_u32(tmp->length) - sizeof(*ske));
                      clib_warning("IKE_SA_INIT retransmit from %U to %U",
                                   format_ip4_address, &raddr,
                                   format_ip4_address, &iaddr);
                      return 1;
                    }
                  /* else ignore req */
                  else
                    {
                      clib_warning("IKE_SA_INIT ignore from %U to %U",
                                   format_ip4_address, &raddr,
                                   format_ip4_address, &iaddr);
                      return -1;
                    }
                }
            }
          payload = skep->nextpayload;
          p+=plen;
        }
      }
  }));
  /* *INDENT-ON* */

  /* req is not retransmit */
  return 0;
}

static int
ske_retransmit_resp (ske_sa_t * sa, ske_header_t * ske)
{
  u32 msg_id = clib_net_to_host_u32 (ske->msgid);

  /* new req */
  if (msg_id > sa->last_msg_id)
    {
      sa->last_msg_id = msg_id;
      return 0;
    }
  /* retransmitted req */
  else if (msg_id == sa->last_msg_id)
    {
      ske_header_t *tmp;
      tmp = (ske_header_t *) sa->last_res_packet_data;
      ske->ispi = tmp->ispi;
      ske->rspi = tmp->rspi;
      ske->nextpayload = tmp->nextpayload;
      ske->version = tmp->version;
      ske->exchange = tmp->exchange;
      ske->flags = tmp->flags;
      ske->msgid = tmp->msgid;
      ske->length = tmp->length;
      clib_memcpy_fast (ske->payload, tmp->payload,
			clib_net_to_host_u32 (tmp->length) - sizeof (*ske));
      clib_warning ("IKE msgid %u retransmit from %U to %U",
		    msg_id,
		    format_ip4_address, &sa->raddr,
		    format_ip4_address, &sa->iaddr);
      return 1;
    }
  /* old req ignore */
  else
    {
      clib_warning ("IKE msgid %u req ignore from %U to %U",
		    msg_id,
		    format_ip4_address, &sa->raddr,
		    format_ip4_address, &sa->iaddr);
      return -1;
    }
}


static uword
ske_node_fn (vlib_main_t * vm,
	       vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 n_left_from, *from, *to_next;
  ske_next_t next_index;
  ske_main_t *km = &ske_main;
  u32 thread_index = vlib_get_thread_index ();

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  u32 next0 = SKE_NEXT_ERROR_DROP;
	  u32 sw_if_index0;
	  ip4_header_t *ip40;
	  udp_header_t *udp0;
	  ske_header_t *ske0;
	  ske_sa_t *sa0 = 0;
	  ske_sa_t sa;	/* temporary store for SA */
	  int len = 0;
	  int r;

	  /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  ske0 = vlib_buffer_get_current (b0);
	  vlib_buffer_advance (b0, -sizeof (*udp0));
	  udp0 = vlib_buffer_get_current (b0);
	  vlib_buffer_advance (b0, -sizeof (*ip40));
	  ip40 = vlib_buffer_get_current (b0);

	  if (ske0->version != IKE_VERSION_2)
	    {
	      vlib_node_increment_counter (vm, ske_node.index,
					   SKE_ERROR_NOT_SKE, 1);
	      goto dispatch0;
	    }

	  if (ske0->exchange == SKE_EXCHANGE_SA_INIT)
	    {
	      sa0 = &sa;
	      clib_memset (sa0, 0, sizeof (*sa0));

	      if (ske0->flags & SKE_HDR_FLAG_INITIATOR)
		{
		  if (ske0->rspi == 0)
		    {
		      sa0->raddr.as_u32 = ip40->dst_address.as_u32;
		      sa0->iaddr.as_u32 = ip40->src_address.as_u32;

		      r = ske_retransmit_sa_init (ske0, sa0->iaddr,
						    sa0->raddr);
		      if (r == 1)
			{
			  vlib_node_increment_counter (vm, ske_node.index,
						       SKE_ERROR_IKE_SA_INIT_RETRANSMIT,
						       1);
			  len = clib_net_to_host_u32 (ske0->length);
			  goto dispatch0;
			}
		      else if (r == -1)
			{
			  vlib_node_increment_counter (vm, ske_node.index,
						       SKE_ERROR_IKE_SA_INIT_IGNORE,
						       1);
			  goto dispatch0;
			}

		      ske_process_sa_init_req (vm, sa0, ske0);

		      if (sa0->state == SKE_STATE_SA_INIT)
			{
			  ske_sa_free_proposal_vector (&sa0->r_proposals);
			  sa0->r_proposals =
			    ske_select_proposal (sa0->i_proposals,
						   SKE_PROTOCOL_IKE);
			  ske_generate_sa_init_data (sa0);
			}

		      if (sa0->state == SKE_STATE_SA_INIT
			  || sa0->state == SKE_STATE_NOTIFY_AND_DELETE)
			{
			  len = ske_generate_message (sa0, ske0, 0);
			}

		      if (sa0->state == SKE_STATE_SA_INIT)
			{
			  /* add SA to the pool */
			  pool_get (km->per_thread_data[thread_index].sas,
				    sa0);
			  clib_memcpy_fast (sa0, &sa, sizeof (*sa0));
			  hash_set (km->
				    per_thread_data[thread_index].sa_by_rspi,
				    sa0->rspi,
				    sa0 -
				    km->per_thread_data[thread_index].sas);
			}
		      else
			{
			  ske_sa_free_all_vec (sa0);
			}
		    }
		}
	      else		//received sa_init without initiator flag
		{
		  ske_process_sa_init_resp (vm, sa0, ske0);

		  if (sa0->state == SKE_STATE_SA_INIT)
		    {
		      ske0->exchange = SKE_EXCHANGE_IKE_AUTH;
		      uword *p = hash_get (km->sa_by_ispi, ske0->ispi);
		      if (p)
			{
			  ske_sa_t *sai =
			    pool_elt_at_index (km->sais, p[0]);

			  ske_complete_sa_data (sa0, sai);
			  ske_calc_keys (sa0);
			  ske_sa_auth_init (sa0);
			  len = ske_generate_message (sa0, ske0, 0);
			}
		    }

		  if (sa0->state == SKE_STATE_SA_INIT)
		    {
		      /* add SA to the pool */
		      pool_get (km->per_thread_data[thread_index].sas, sa0);
		      clib_memcpy_fast (sa0, &sa, sizeof (*sa0));
		      hash_set (km->per_thread_data[thread_index].sa_by_rspi,
				sa0->rspi,
				sa0 - km->per_thread_data[thread_index].sas);
		    }
		  else
		    {
		      ske_sa_free_all_vec (sa0);
		    }
		}
	    }
	  else if (ske0->exchange == SKE_EXCHANGE_IKE_AUTH)
	    {
	      uword *p;
	      p = hash_get (km->per_thread_data[thread_index].sa_by_rspi,
			    clib_net_to_host_u64 (ske0->rspi));
	      if (p)
		{
		  sa0 =
		    pool_elt_at_index (km->per_thread_data[thread_index].sas,
				       p[0]);

		  r = ske_retransmit_resp (sa0, ske0);
		  if (r == 1)
		    {
		      vlib_node_increment_counter (vm, ske_node.index,
						   SKE_ERROR_IKE_REQ_RETRANSMIT,
						   1);
		      len = clib_net_to_host_u32 (ske0->length);
		      goto dispatch0;
		    }
		  else if (r == -1)
		    {
		      vlib_node_increment_counter (vm, ske_node.index,
						   SKE_ERROR_IKE_REQ_IGNORE,
						   1);
		      goto dispatch0;
		    }

		  ske_process_auth_req (vm, sa0, ske0);
		  ske_sa_auth (sa0);
		  if (sa0->state == SKE_STATE_AUTHENTICATED)
		    {
		      ske_initial_contact_cleanup (sa0);
		      ske_sa_match_ts (sa0);
		      if (sa0->state != SKE_STATE_TS_UNACCEPTABLE)
			ske_create_tunnel_interface (km->vnet_main, sa0,
						       &sa0->childs[0]);
		    }

		  if (sa0->is_initiator)
		    {
		      uword *p = hash_get (km->sa_by_ispi, ske0->ispi);
		      if (p)
			{
			  ske_sa_t *sai =
			    pool_elt_at_index (km->sais, p[0]);
			  hash_unset (km->sa_by_ispi, sai->ispi);
			  ske_sa_free_all_vec (sai);
			  pool_put (km->sais, sai);
			}
		    }
		  else
		    {
		      len = ske_generate_message (sa0, ske0, 0);
		    }
		}
	    }
	  else if (ske0->exchange == SKE_EXCHANGE_INFORMATIONAL)
	    {
	      uword *p;
	      p = hash_get (km->per_thread_data[thread_index].sa_by_rspi,
			    clib_net_to_host_u64 (ske0->rspi));
	      if (p)
		{
		  sa0 =
		    pool_elt_at_index (km->per_thread_data[thread_index].sas,
				       p[0]);

		  r = ske_retransmit_resp (sa0, ske0);
		  if (r == 1)
		    {
		      vlib_node_increment_counter (vm, ske_node.index,
						   SKE_ERROR_IKE_REQ_RETRANSMIT,
						   1);
		      len = clib_net_to_host_u32 (ske0->length);
		      goto dispatch0;
		    }
		  else if (r == -1)
		    {
		      vlib_node_increment_counter (vm, ske_node.index,
						   SKE_ERROR_IKE_REQ_IGNORE,
						   1);
		      goto dispatch0;
		    }

		  ske_process_informational_req (vm, sa0, ske0);
		  if (sa0->del)
		    {
		      if (sa0->del[0].protocol_id != SKE_PROTOCOL_IKE)
			{
			  ske_delete_t *d, *tmp, *resp = 0;
			  vec_foreach (d, sa0->del)
			  {
			    ske_child_sa_t *ch_sa;
			    ch_sa = ske_sa_get_child (sa0, d->spi,
							d->protocol_id,
							!sa0->is_initiator);
			    if (ch_sa)
			      {
				ske_delete_tunnel_interface (km->vnet_main,
							       sa0, ch_sa);
				if (!sa0->is_initiator)
				  {
				    vec_add2 (resp, tmp, 1);
				    tmp->protocol_id = d->protocol_id;
				    tmp->spi = ch_sa->r_proposals[0].spi;
				  }
				ske_sa_del_child_sa (sa0, ch_sa);
			      }
			  }
			  if (!sa0->is_initiator)
			    {
			      vec_free (sa0->del);
			      sa0->del = resp;
			    }
			}
		    }
		  if (!sa0->is_initiator)
		    {
		      len = ske_generate_message (sa0, ske0, 0);
		    }
		}
	    }
	  else if (ske0->exchange == SKE_EXCHANGE_CREATE_CHILD_SA)
	    {
	      uword *p;
	      p = hash_get (km->per_thread_data[thread_index].sa_by_rspi,
			    clib_net_to_host_u64 (ske0->rspi));
	      if (p)
		{
		  sa0 =
		    pool_elt_at_index (km->per_thread_data[thread_index].sas,
				       p[0]);

		  r = ske_retransmit_resp (sa0, ske0);
		  if (r == 1)
		    {
		      vlib_node_increment_counter (vm, ske_node.index,
						   SKE_ERROR_IKE_REQ_RETRANSMIT,
						   1);
		      len = clib_net_to_host_u32 (ske0->length);
		      goto dispatch0;
		    }
		  else if (r == -1)
		    {
		      vlib_node_increment_counter (vm, ske_node.index,
						   SKE_ERROR_IKE_REQ_IGNORE,
						   1);
		      goto dispatch0;
		    }

		  ske_process_create_child_sa_req (vm, sa0, ske0);
		  if (sa0->rekey)
		    {
		      if (sa0->rekey[0].protocol_id != SKE_PROTOCOL_IKE)
			{
			  ske_child_sa_t *child;
			  vec_add2 (sa0->childs, child, 1);
			  child->r_proposals = sa0->rekey[0].r_proposal;
			  child->i_proposals = sa0->rekey[0].i_proposal;
			  child->tsi = sa0->rekey[0].tsi;
			  child->tsr = sa0->rekey[0].tsr;
			  ske_create_tunnel_interface (km->vnet_main, sa0,
							 child);
			}
		      if (sa0->is_initiator)
			{
			  vec_del1 (sa0->rekey, 0);
			}
		      else
			{
			  len = ske_generate_message (sa0, ske0, 0);
			}
		    }
		}
	    }
	  else
	    {
	      clib_warning ("SKE exchange %u packet received from %U to %U",
			    ske0->exchange,
			    format_ip4_address, ip40->src_address.as_u8,
			    format_ip4_address, ip40->dst_address.as_u8);
	    }

	dispatch0:
	  /* if we are sending packet back, rewrite headers */
	  if (len)
	    {
	      next0 = SKE_NEXT_IP4_LOOKUP;
	      if (sa0->is_initiator)
		{
		  ip40->dst_address.as_u32 = sa0->raddr.as_u32;
		  ip40->src_address.as_u32 = sa0->iaddr.as_u32;
		}
	      else
		{
		  ip40->dst_address.as_u32 = sa0->iaddr.as_u32;
		  ip40->src_address.as_u32 = sa0->raddr.as_u32;
		}
	      udp0->length =
		clib_host_to_net_u16 (len + sizeof (udp_header_t));
	      udp0->checksum = 0;
	      b0->current_length =
		len + sizeof (ip4_header_t) + sizeof (udp_header_t);
	      ip40->length = clib_host_to_net_u16 (b0->current_length);
	      ip40->checksum = ip4_header_checksum (ip40);
	    }
	  /* delete sa */
	  if (sa0 && (sa0->state == SKE_STATE_DELETED ||
		      sa0->state == SKE_STATE_NOTIFY_AND_DELETE))
	    {
	      ske_child_sa_t *c;

	      vec_foreach (c, sa0->childs)
		ske_delete_tunnel_interface (km->vnet_main, sa0, c);

	      ske_delete_sa (sa0);
	    }
	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			     && (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      ske_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->sw_if_index = sw_if_index0;
	      t->next_index = next0;
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, ske_node.index,
			       SKE_ERROR_PROCESSED, frame->n_vectors);
  return frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ske_node,static) = {
  .function = ske_node_fn,
  .name = "ske",
  .vector_size = sizeof (u32),
  .format_trace = format_ske_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(ske_error_strings),
  .error_strings = ske_error_strings,

  .n_next_nodes = SKE_N_NEXT,

  .next_nodes = {
    [SKE_NEXT_IP4_LOOKUP] = "ip4-lookup",
        [SKE_NEXT_ERROR_DROP] = "error-drop",
  },
};
/* *INDENT-ON* */

// set ske proposals when vpp is used as initiator
static clib_error_t *
ske_set_initiator_proposals (vlib_main_t * vm, ske_sa_t * sa,
			       ske_transforms_set * ts,
			       ske_sa_proposal_t ** proposals, int is_ske)
{
  clib_error_t *r;
  ske_main_t *km = &ske_main;
  ske_sa_proposal_t *proposal;
  vec_add2 (*proposals, proposal, 1);
  ske_sa_transform_t *td;
  int error;

  /* Encryption */
  error = 1;
  vec_foreach (td, km->supported_transforms)
  {
    if (td->type == SKE_TRANSFORM_TYPE_ENCR
	&& td->encr_type == ts->crypto_alg
	&& td->key_len == ts->crypto_key_size / 8)
      {
	u16 attr[2];
	attr[0] = clib_host_to_net_u16 (14 | (1 << 15));
	attr[1] = clib_host_to_net_u16 (td->key_len << 3);
	vec_add (td->attrs, (u8 *) attr, 4);
	vec_add1 (proposal->transforms, *td);
	td->attrs = 0;

	error = 0;
	break;
      }
  }
  if (error)
    {
      r = clib_error_return (0, "Unsupported algorithm");
      return r;
    }

  /* Integrity */
  error = 1;
  vec_foreach (td, km->supported_transforms)
  {
    if (td->type == SKE_TRANSFORM_TYPE_INTEG
	&& td->integ_type == ts->integ_alg)
      {
	vec_add1 (proposal->transforms, *td);
	error = 0;
	break;
      }
  }
  if (error)
    {
      clib_warning
	("Didn't find any supported algorithm for SKE_TRANSFORM_TYPE_INTEG");
      r = clib_error_return (0, "Unsupported algorithm");
      return r;
    }

  /* PRF */
  if (is_ske)
    {
      error = 1;
      vec_foreach (td, km->supported_transforms)
      {
	if (td->type == SKE_TRANSFORM_TYPE_PRF
	    && td->prf_type == SKE_TRANSFORM_PRF_TYPE_PRF_HMAC_SHA2_256)
	  {
	    vec_add1 (proposal->transforms, *td);
	    error = 0;
	    break;
	  }
      }
      if (error)
	{
	  r = clib_error_return (0, "Unsupported algorithm");
	  return r;
	}
    }

  /* DH */
  error = 1;
  vec_foreach (td, km->supported_transforms)
  {
    if (td->type == SKE_TRANSFORM_TYPE_DH && td->dh_type == ts->dh_type)
      {
	vec_add1 (proposal->transforms, *td);
	if (is_ske)
	  {
	    sa->dh_group = td->dh_type;
	  }
	error = 0;
	break;
      }
  }
  if (error)
    {
      r = clib_error_return (0, "Unsupported algorithm");
      return r;
    }

  if (!is_ske)
    {
      error = 1;
      vec_foreach (td, km->supported_transforms)
      {
	if (td->type == SKE_TRANSFORM_TYPE_ESN)
	  {
	    vec_add1 (proposal->transforms, *td);
	    error = 0;
	    break;
	  }
      }
      if (error)
	{
	  r = clib_error_return (0, "Unsupported algorithm");
	  return r;
	}
    }


  return 0;
}

static ske_profile_t *
ske_profile_index_by_name (u8 * name)
{
  ske_main_t *km = &ske_main;
  uword *p;

  p = mhash_get (&km->profile_index_by_name, name);
  if (!p)
    return 0;

  return pool_elt_at_index (km->profiles, p[0]);
}


static void
ske_send_ske (vlib_main_t * vm, ip4_address_t * src, ip4_address_t * dst,
		u32 bi0, u32 len)
{
  ip4_header_t *ip40;
  udp_header_t *udp0;
  vlib_buffer_t *b0;
  vlib_frame_t *f;
  u32 *to_next;

  b0 = vlib_get_buffer (vm, bi0);
  vlib_buffer_advance (b0, -sizeof (udp_header_t));
  udp0 = vlib_buffer_get_current (b0);
  vlib_buffer_advance (b0, -sizeof (ip4_header_t));
  ip40 = vlib_buffer_get_current (b0);


  ip40->ip_version_and_header_length = 0x45;
  ip40->tos = 0;
  ip40->fragment_id = 0;
  ip40->flags_and_fragment_offset = 0;
  ip40->ttl = 0xff;
  ip40->protocol = IP_PROTOCOL_UDP;
  ip40->dst_address.as_u32 = dst->as_u32;
  ip40->src_address.as_u32 = src->as_u32;
  udp0->dst_port = clib_host_to_net_u16 (500);
  udp0->src_port = clib_host_to_net_u16 (500);
  udp0->length = clib_host_to_net_u16 (len + sizeof (udp_header_t));
  udp0->checksum = 0;
  b0->current_length = len + sizeof (ip4_header_t) + sizeof (udp_header_t);
  ip40->length = clib_host_to_net_u16 (b0->current_length);
  ip40->checksum = ip4_header_checksum (ip40);


  /* send the request */
  f = vlib_get_frame_to_node (vm, ip4_lookup_node.index);
  to_next = vlib_frame_vector_args (f);
  to_next[0] = bi0;
  f->n_vectors = 1;
  vlib_put_frame_to_node (vm, ip4_lookup_node.index, f);

}

static u32
ske_get_new_ske_header_buff (vlib_main_t * vm, ske_header_t ** ske)
{
  u32 bi0;
  if (vlib_buffer_alloc (vm, &bi0, 1) != 1)
    {
      *ske = 0;
      return 0;
    }
  vlib_buffer_t *b0 = vlib_get_buffer (vm, bi0);
  *ske = vlib_buffer_get_current (b0);
  return bi0;
}

clib_error_t *
ske_set_local_key (vlib_main_t * vm, u8 * file)
{
  ske_main_t *km = &ske_main;

  km->pkey = ske_load_key_file (file);
  if (km->pkey == NULL)
    return clib_error_return (0, "load key '%s' failed", file);

  return 0;
}

clib_error_t *
ske_add_del_profile (vlib_main_t * vm, u8 * name, int is_add)
{
  ske_main_t *km = &ske_main;
  ske_profile_t *p;

  if (is_add)
    {
      if (ske_profile_index_by_name (name))
	return clib_error_return (0, "policy %v already exists", name);

      pool_get (km->profiles, p);
      clib_memset (p, 0, sizeof (*p));
      p->name = vec_dup (name);
      p->responder.sw_if_index = ~0;
      uword index = p - km->profiles;
      mhash_set_mem (&km->profile_index_by_name, name, &index, 0);
    }
  else
    {
      p = ske_profile_index_by_name (name);
      if (!p)
	return clib_error_return (0, "policy %v does not exists", name);

      vec_free (p->name);
      pool_put (km->profiles, p);
      mhash_unset (&km->profile_index_by_name, name, 0);
    }
  return 0;
}

clib_error_t *
ske_set_profile_auth (vlib_main_t * vm, u8 * name, u8 auth_method,
			u8 * auth_data, u8 data_hex_format)
{
  ske_profile_t *p;
  clib_error_t *r;

  p = ske_profile_index_by_name (name);

  if (!p)
    {
      r = clib_error_return (0, "unknown profile %v", name);
      return r;
    }
  vec_free (p->auth.data);
  p->auth.method = auth_method;
  p->auth.data = vec_dup (auth_data);
  p->auth.hex = data_hex_format;

  if (auth_method == SKE_AUTH_METHOD_RSA_SIG)
    {
      vec_add1 (p->auth.data, 0);
      if (p->auth.key)
	EVP_PKEY_free (p->auth.key);
      p->auth.key = ske_load_cert_file (auth_data);
      if (p->auth.key == NULL)
	return clib_error_return (0, "load cert '%s' failed", auth_data);
    }

  return 0;
}

clib_error_t *
ske_set_profile_id (vlib_main_t * vm, u8 * name, u8 id_type, u8 * data,
		      int is_local)
{
  ske_profile_t *p;
  clib_error_t *r;

  if (id_type > SKE_ID_TYPE_ID_RFC822_ADDR
      && id_type < SKE_ID_TYPE_ID_KEY_ID)
    {
      r = clib_error_return (0, "unsupported identity type %U",
			     format_ske_id_type, id_type);
      return r;
    }

  p = ske_profile_index_by_name (name);

  if (!p)
    {
      r = clib_error_return (0, "unknown profile %v", name);
      return r;
    }

  if (is_local)
    {
      vec_free (p->loc_id.data);
      p->loc_id.type = id_type;
      p->loc_id.data = vec_dup (data);
    }
  else
    {
      vec_free (p->rem_id.data);
      p->rem_id.type = id_type;
      p->rem_id.data = vec_dup (data);
    }

  return 0;
}

clib_error_t *
ske_set_profile_ts (vlib_main_t * vm, u8 * name, u8 protocol_id,
		      u16 start_port, u16 end_port, ip4_address_t start_addr,
		      ip4_address_t end_addr, int is_local)
{
  ske_profile_t *p;
  clib_error_t *r;

  p = ske_profile_index_by_name (name);

  if (!p)
    {
      r = clib_error_return (0, "unknown profile %v", name);
      return r;
    }

  if (is_local)
    {
      p->loc_ts.start_addr.as_u32 = start_addr.as_u32;
      p->loc_ts.end_addr.as_u32 = end_addr.as_u32;
      p->loc_ts.start_port = start_port;
      p->loc_ts.end_port = end_port;
      p->loc_ts.protocol_id = protocol_id;
      p->loc_ts.ts_type = 7;
    }
  else
    {
      p->rem_ts.start_addr.as_u32 = start_addr.as_u32;
      p->rem_ts.end_addr.as_u32 = end_addr.as_u32;
      p->rem_ts.start_port = start_port;
      p->rem_ts.end_port = end_port;
      p->rem_ts.protocol_id = protocol_id;
      p->rem_ts.ts_type = 7;
    }

  return 0;
}


clib_error_t *
ske_set_profile_responder (vlib_main_t * vm, u8 * name,
			     u32 sw_if_index, ip4_address_t ip4)
{
  ske_profile_t *p;
  clib_error_t *r;

  p = ske_profile_index_by_name (name);

  if (!p)
    {
      r = clib_error_return (0, "unknown profile %v", name);
      return r;
    }

  p->responder.sw_if_index = sw_if_index;
  p->responder.ip4 = ip4;

  return 0;
}

clib_error_t *
ske_set_profile_ske_transforms (vlib_main_t * vm, u8 * name,
				  ske_transform_encr_type_t crypto_alg,
				  ske_transform_integ_type_t integ_alg,
				  ske_transform_dh_type_t dh_type,
				  u32 crypto_key_size)
{
  ske_profile_t *p;
  clib_error_t *r;

  p = ske_profile_index_by_name (name);

  if (!p)
    {
      r = clib_error_return (0, "unknown profile %v", name);
      return r;
    }

  p->ske_ts.crypto_alg = crypto_alg;
  p->ske_ts.integ_alg = integ_alg;
  p->ske_ts.dh_type = dh_type;
  p->ske_ts.crypto_key_size = crypto_key_size;
  return 0;
}

clib_error_t *
ske_set_profile_esp_transforms (vlib_main_t * vm, u8 * name,
				  ske_transform_encr_type_t crypto_alg,
				  ske_transform_integ_type_t integ_alg,
				  ske_transform_dh_type_t dh_type,
				  u32 crypto_key_size)
{
  ske_profile_t *p;
  clib_error_t *r;

  p = ske_profile_index_by_name (name);

  if (!p)
    {
      r = clib_error_return (0, "unknown profile %v", name);
      return r;
    }

  p->esp_ts.crypto_alg = crypto_alg;
  p->esp_ts.integ_alg = integ_alg;
  p->esp_ts.dh_type = dh_type;
  p->esp_ts.crypto_key_size = crypto_key_size;
  return 0;
}

clib_error_t *
ske_set_profile_sa_lifetime (vlib_main_t * vm, u8 * name,
			       u64 lifetime, u32 jitter, u32 handover,
			       u64 maxdata)
{
  ske_profile_t *p;
  clib_error_t *r;

  p = ske_profile_index_by_name (name);

  if (!p)
    {
      r = clib_error_return (0, "unknown profile %v", name);
      return r;
    }

  p->lifetime = lifetime;
  p->lifetime_jitter = jitter;
  p->handover = handover;
  p->lifetime_maxdata = maxdata;
  return 0;
}

clib_error_t *
ske_initiate_sa_init (vlib_main_t * vm, u8 * name)
{
  ske_profile_t *p;
  clib_error_t *r;
  ip4_main_t *im = &ip4_main;
  ske_main_t *km = &ske_main;

  p = ske_profile_index_by_name (name);

  if (!p)
    {
      r = clib_error_return (0, "unknown profile %v", name);
      return r;
    }

  if (p->responder.sw_if_index == ~0 || p->responder.ip4.data_u32 == 0)
    {
      r = clib_error_return (0, "responder not set for profile %v", name);
      return r;
    }


  /* Create the Initiator Request */
  {
    ske_header_t *ske0;
    u32 bi0 = 0;
    ip_lookup_main_t *lm = &im->lookup_main;
    u32 if_add_index0;
    int len = sizeof (ske_header_t);

    /* Get own iface IP */
    if_add_index0 =
      lm->if_address_pool_index_by_sw_if_index[p->responder.sw_if_index];
    ip_interface_address_t *if_add =
      pool_elt_at_index (lm->if_address_pool, if_add_index0);
    ip4_address_t *if_ip = ip_interface_address_get_address (lm, if_add);

    bi0 = ske_get_new_ske_header_buff (vm, &ske0);

    /* Prepare the SA and the IKE payload */
    ske_sa_t sa;
    clib_memset (&sa, 0, sizeof (ske_sa_t));
    ske_payload_chain_t *chain = 0;
    ske_payload_new_chain (chain);

    /* Build the IKE proposal payload */
    ske_sa_proposal_t *proposals = 0;
    ske_set_initiator_proposals (vm, &sa, &p->ske_ts, &proposals, 1);
    proposals[0].proposal_num = 1;
    proposals[0].protocol_id = SKE_PROTOCOL_IKE;

    /* Add and then cleanup proposal data */
    ske_payload_add_sa (chain, proposals);
    ske_sa_free_proposal_vector (&proposals);

    sa.is_initiator = 1;
    sa.profile_index = km->profiles - p;
    sa.is_profile_index_set = 1;
    sa.state = SKE_STATE_SA_INIT;
    ske_generate_sa_init_data (&sa);
    ske_payload_add_ke (chain, sa.dh_group, sa.i_dh_data);
    ske_payload_add_nonce (chain, sa.i_nonce);

    /* Build the child SA proposal */
    vec_resize (sa.childs, 1);
    ske_set_initiator_proposals (vm, &sa, &p->esp_ts,
				   &sa.childs[0].i_proposals, 0);
    sa.childs[0].i_proposals[0].proposal_num = 1;
    sa.childs[0].i_proposals[0].protocol_id = SKE_PROTOCOL_ESP;
    RAND_bytes ((u8 *) & sa.childs[0].i_proposals[0].spi,
		sizeof (sa.childs[0].i_proposals[0].spi));



    /* Add NAT detection notification messages (mandatory) */
    u8 nat_detection_source[8 + 8 + 4 + 2];
    u8 *nat_detection_sha1 = vec_new (u8, 20);

    u64 tmpspi = clib_host_to_net_u64 (sa.ispi);
    clib_memcpy_fast (&nat_detection_source[0], &tmpspi, sizeof (tmpspi));
    tmpspi = clib_host_to_net_u64 (sa.rspi);
    clib_memcpy_fast (&nat_detection_source[8], &tmpspi, sizeof (tmpspi));
    u16 tmpport = clib_host_to_net_u16 (500);
    clib_memcpy_fast (&nat_detection_source[8 + 8 + 4], &tmpport,
		      sizeof (tmpport));
    u32 tmpip = clib_host_to_net_u32 (if_ip->as_u32);
    clib_memcpy_fast (&nat_detection_source[8 + 8], &tmpip, sizeof (tmpip));
    SHA1 (nat_detection_source, sizeof (nat_detection_source),
	  nat_detection_sha1);
    ske_payload_add_notify (chain, SKE_NOTIFY_MSG_NAT_DETECTION_SOURCE_IP,
			      nat_detection_sha1);
    tmpip = clib_host_to_net_u32 (p->responder.ip4.as_u32);
    clib_memcpy_fast (&nat_detection_source[8 + 8], &tmpip, sizeof (tmpip));
    SHA1 (nat_detection_source, sizeof (nat_detection_source),
	  nat_detection_sha1);
    ske_payload_add_notify (chain,
			      SKE_NOTIFY_MSG_NAT_DETECTION_DESTINATION_IP,
			      nat_detection_sha1);
    vec_free (nat_detection_sha1);

    u8 *sig_hash_algo = vec_new (u8, 8);
    u64 tmpsig = clib_host_to_net_u64 (0x0001000200030004);
    clib_memcpy_fast (sig_hash_algo, &tmpsig, sizeof (tmpsig));
    ske_payload_add_notify (chain,
			      SKE_NOTIFY_MSG_SIGNATURE_HASH_ALGORITHMS,
			      sig_hash_algo);
    vec_free (sig_hash_algo);


    /* Buffer update and boilerplate */
    len += vec_len (chain->data);
    ske0->nextpayload = chain->first_payload_type;
    ske0->length = clib_host_to_net_u32 (len);
    clib_memcpy_fast (ske0->payload, chain->data, vec_len (chain->data));
    ske_payload_destroy_chain (chain);

    ske0->version = IKE_VERSION_2;
    ske0->flags = SKE_HDR_FLAG_INITIATOR;
    ske0->exchange = SKE_EXCHANGE_SA_INIT;
    ske0->ispi = sa.ispi;
    ske0->rspi = 0;

    /* store whole IKE payload - needed for PSK auth */
    vec_free (sa.last_sa_init_req_packet_data);
    vec_add (sa.last_sa_init_req_packet_data, ske0, len);

    /* add data to the SA then add it to the pool */
    sa.iaddr.as_u32 = if_ip->as_u32;
    sa.raddr.as_u32 = p->responder.ip4.as_u32;
    sa.i_id.type = p->loc_id.type;
    sa.i_id.data = vec_dup (p->loc_id.data);
    sa.i_auth.method = p->auth.method;
    sa.i_auth.hex = p->auth.hex;
    sa.i_auth.data = vec_dup (p->auth.data);
    vec_add (sa.childs[0].tsi, &p->loc_ts, 1);
    vec_add (sa.childs[0].tsr, &p->rem_ts, 1);

    /* add SA to the pool */
    ske_sa_t *sa0 = 0;
    pool_get (km->sais, sa0);
    clib_memcpy_fast (sa0, &sa, sizeof (*sa0));
    hash_set (km->sa_by_ispi, sa0->ispi, sa0 - km->sais);

    ske_send_ske (vm, if_ip, &p->responder.ip4, bi0, len);

  }

  return 0;
}

static void
ske_delete_child_sa_internal (vlib_main_t * vm, ske_sa_t * sa,
				ske_child_sa_t * csa)
{
  /* Create the Initiator notification for child SA removal */
  ske_main_t *km = &ske_main;
  ske_header_t *ske0;
  u32 bi0 = 0;
  int len;

  bi0 = ske_get_new_ske_header_buff (vm, &ske0);


  ske0->exchange = SKE_EXCHANGE_INFORMATIONAL;
  ske0->ispi = clib_host_to_net_u64 (sa->ispi);
  ske0->rspi = clib_host_to_net_u64 (sa->rspi);
  vec_resize (sa->del, 1);
  sa->del->protocol_id = SKE_PROTOCOL_ESP;
  sa->del->spi = csa->i_proposals->spi;
  ske0->msgid = clib_host_to_net_u32 (sa->last_init_msg_id + 1);
  sa->last_init_msg_id = clib_net_to_host_u32 (ske0->msgid);
  len = ske_generate_message (sa, ske0, 0);

  ske_send_ske (vm, &sa->iaddr, &sa->raddr, bi0, len);

  /* delete local child SA */
  ske_delete_tunnel_interface (km->vnet_main, sa, csa);
  ske_sa_del_child_sa (sa, csa);
}

clib_error_t *
ske_initiate_delete_child_sa (vlib_main_t * vm, u32 ispi)
{
  clib_error_t *r;
  ske_main_t *km = &ske_main;
  ske_main_per_thread_data_t *tkm;
  ske_sa_t *fsa = 0;
  ske_child_sa_t *fchild = 0;

  /* Search for the child SA */
  vec_foreach (tkm, km->per_thread_data)
  {
    ske_sa_t *sa;
    if (fchild)
      break;
    /* *INDENT-OFF* */
    pool_foreach (sa, tkm->sas, ({
      fchild = ske_sa_get_child(sa, ispi, SKE_PROTOCOL_ESP, 1);
      if (fchild)
        {
          fsa = sa;
          break;
        }
    }));
    /* *INDENT-ON* */
  }

  if (!fchild || !fsa)
    {
      r = clib_error_return (0, "Child SA not found");
      return r;
    }
  else
    {
      ske_delete_child_sa_internal (vm, fsa, fchild);
    }

  return 0;
}

clib_error_t *
ske_initiate_delete_ske_sa (vlib_main_t * vm, u64 ispi)
{
  clib_error_t *r;
  ske_main_t *km = &ske_main;
  ske_main_per_thread_data_t *tkm;
  ske_sa_t *fsa = 0;
  ske_main_per_thread_data_t *ftkm = 0;

  /* Search for the IKE SA */
  vec_foreach (tkm, km->per_thread_data)
  {
    ske_sa_t *sa;
    if (fsa)
      break;
    /* *INDENT-OFF* */
    pool_foreach (sa, tkm->sas, ({
      if (sa->ispi == ispi)
        {
          fsa = sa;
          ftkm = tkm;
          break;
        }
    }));
    /* *INDENT-ON* */
  }

  if (!fsa)
    {
      r = clib_error_return (0, "IKE SA not found");
      return r;
    }


  /* Create the Initiator notification for IKE SA removal */
  {
    ske_header_t *ske0;
    u32 bi0 = 0;
    int len;

    bi0 = ske_get_new_ske_header_buff (vm, &ske0);


    ske0->exchange = SKE_EXCHANGE_INFORMATIONAL;
    ske0->ispi = clib_host_to_net_u64 (fsa->ispi);
    ske0->rspi = clib_host_to_net_u64 (fsa->rspi);
    vec_resize (fsa->del, 1);
    fsa->del->protocol_id = SKE_PROTOCOL_IKE;
    fsa->del->spi = ispi;
    ske0->msgid = clib_host_to_net_u32 (fsa->last_init_msg_id + 1);
    fsa->last_init_msg_id = clib_net_to_host_u32 (ske0->msgid);
    len = ske_generate_message (fsa, ske0, 0);

    ske_send_ske (vm, &fsa->iaddr, &fsa->raddr, bi0, len);
  }


  /* delete local SA */
  ske_child_sa_t *c;
  vec_foreach (c, fsa->childs)
  {
    ske_delete_tunnel_interface (km->vnet_main, fsa, c);
    ske_sa_del_child_sa (fsa, c);
  }
  ske_sa_free_all_vec (fsa);
  uword *p = hash_get (ftkm->sa_by_rspi, fsa->rspi);
  if (p)
    {
      hash_unset (ftkm->sa_by_rspi, fsa->rspi);
      pool_put (ftkm->sas, fsa);
    }


  return 0;
}

static void
ske_rekey_child_sa_internal (vlib_main_t * vm, ske_sa_t * sa,
			       ske_child_sa_t * csa)
{
  /* Create the Initiator request for create child SA */
  ske_header_t *ske0;
  u32 bi0 = 0;
  int len;


  bi0 = ske_get_new_ske_header_buff (vm, &ske0);


  ske0->version = IKE_VERSION_2;
  ske0->flags = SKE_HDR_FLAG_INITIATOR;
  ske0->exchange = SKE_EXCHANGE_CREATE_CHILD_SA;
  ske0->ispi = clib_host_to_net_u64 (sa->ispi);
  ske0->rspi = clib_host_to_net_u64 (sa->rspi);
  ske0->msgid = clib_host_to_net_u32 (sa->last_init_msg_id + 1);
  sa->last_init_msg_id = clib_net_to_host_u32 (ske0->msgid);

  ske_rekey_t *rekey;
  vec_add2 (sa->rekey, rekey, 1);
  ske_sa_proposal_t *proposals = vec_dup (csa->i_proposals);

  /*need new ispi */
  RAND_bytes ((u8 *) & proposals[0].spi, sizeof (proposals[0].spi));
  rekey->spi = proposals[0].spi;
  rekey->ispi = csa->i_proposals->spi;
  len = ske_generate_message (sa, ske0, proposals);
  ske_send_ske (vm, &sa->iaddr, &sa->raddr, bi0, len);
  vec_free (proposals);
}

clib_error_t *
ske_initiate_rekey_child_sa (vlib_main_t * vm, u32 ispi)
{
  clib_error_t *r;
  ske_main_t *km = &ske_main;
  ske_main_per_thread_data_t *tkm;
  ske_sa_t *fsa = 0;
  ske_child_sa_t *fchild = 0;

  /* Search for the child SA */
  vec_foreach (tkm, km->per_thread_data)
  {
    ske_sa_t *sa;
    if (fchild)
      break;
    /* *INDENT-OFF* */
    pool_foreach (sa, tkm->sas, ({
      fchild = ske_sa_get_child(sa, ispi, SKE_PROTOCOL_ESP, 1);
      if (fchild)
        {
          fsa = sa;
          break;
        }
    }));
    /* *INDENT-ON* */
  }

  if (!fchild || !fsa)
    {
      r = clib_error_return (0, "Child SA not found");
      return r;
    }
  else
    {
      ske_rekey_child_sa_internal (vm, fsa, fchild);
    }

  return 0;
}

clib_error_t *
ske_destroy_enclave (vlib_main_t * vm)
{
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  ret = sgx_destroy_enclave(e_enclave_id);
  
  if(ret != SGX_SUCCESS){
    clib_warning("Failed to destroy enclave (ret=0x%x)", ret);
  }

  return 0;
}

clib_error_t *
ske_init (vlib_main_t * vm)
{
  ske_main_t *km = &ske_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  int thread_id;

  /* enclave loading */
  if(load_enclave() != SGX_SUCCESS){
    clib_warning("Failed to load enclave");
  }
  clib_warning("Succeed to load enclave");

  clib_memset (km, 0, sizeof (ske_main_t));
  km->vnet_main = vnet_get_main ();
  km->vlib_main = vm;

  ske_crypto_init (km);

  mhash_init_vec_string (&km->profile_index_by_name, sizeof (uword));

  vec_validate (km->per_thread_data, tm->n_vlib_mains - 1);
  for (thread_id = 0; thread_id < tm->n_vlib_mains - 1; thread_id++)
    {
      km->per_thread_data[thread_id].sa_by_rspi =
	hash_create (0, sizeof (uword));
    }

  km->sa_by_ispi = hash_create (0, sizeof (uword));

  udp_register_dst_port (vm, 500, ske_node.index, 1);

  ske_cli_reference ();

  return 0;
}

/* *INDENT-OFF* */
VLIB_INIT_FUNCTION (ske_init) =
{
  .runs_after = VLIB_INITS("ipsec_init"),
};
/* *INDENT-ON* */


static u8
ske_mngr_process_child_sa (ske_sa_t * sa, ske_child_sa_t * csa)
{
  ske_main_t *km = &ske_main;
  ske_profile_t *p = 0;
  vlib_main_t *vm = km->vlib_main;
  f64 now = vlib_time_now (vm);
  u8 res = 0;

  if(sa->is_profile_index_set)
    p = pool_elt_at_index(km->profiles, sa->profile_index);

  if (sa->is_initiator && p && csa->time_to_expiration
      && now > csa->time_to_expiration)
    {
      if (!csa->is_expired || csa->rekey_retries > 0)
	{
	  ske_rekey_child_sa_internal (vm, sa, csa);
	  csa->time_to_expiration = now + p->handover;
	  csa->is_expired = 1;
	  if (csa->rekey_retries == 0)
	    {
	      csa->rekey_retries = 5;
	    }
	  else if (csa->rekey_retries > 0)
	    {
	      csa->rekey_retries--;
	      clib_warning ("Rekeying Child SA 0x%x, retries left %d",
			    csa->i_proposals->spi, csa->rekey_retries);
	      if (csa->rekey_retries == 0)
		{
		  csa->rekey_retries = -1;
		}
	    }
	  res |= 1;
	}
      else
	{
	  csa->time_to_expiration = 0;
	  ske_delete_child_sa_internal (vm, sa, csa);
	  res |= 1;
	}
    }

  return res;
}

static void
ske_mngr_process_ipsec_sa (ipsec_sa_t * ipsec_sa)
{
  ske_main_t *km = &ske_main;
  vlib_main_t *vm = km->vlib_main;
  ske_main_per_thread_data_t *tkm;
  ske_sa_t *fsa = 0;
  ske_profile_t *p = 0;
  ske_child_sa_t *fchild = 0;
  f64 now = vlib_time_now (vm);
  vlib_counter_t counts;

  /* Search for the SA and child SA */
  vec_foreach (tkm, km->per_thread_data)
  {
    ske_sa_t *sa;
    if (fchild)
      break;
    /* *INDENT-OFF* */
    pool_foreach (sa, tkm->sas, ({
      fchild = ske_sa_get_child(sa, ipsec_sa->spi, SKE_PROTOCOL_ESP, 1);
      if (fchild)
        {
          fsa = sa;
          break;
        }
    }));
    /* *INDENT-ON* */
  }
  vlib_get_combined_counter (&ipsec_sa_counters,
			     ipsec_sa->stat_index, &counts);

  if(fsa && fsa->is_profile_index_set)
    p = pool_elt_at_index(km->profiles, fsa->profile_index);

  if (fchild && p && p->lifetime_maxdata)
    {
      if (!fchild->is_expired
	  && counts.bytes > p->lifetime_maxdata)
	{
	  fchild->time_to_expiration = now;
	}
    }
}

static vlib_node_registration_t ske_mngr_process_node;

static uword
ske_mngr_process_fn (vlib_main_t * vm, vlib_node_runtime_t * rt,
		       vlib_frame_t * f)
{
  ske_main_t *km = &ske_main;
  ipsec_main_t *im = &ipsec_main;

  while (1)
    {
      u8 req_sent = 0;
      vlib_process_wait_for_event_or_clock (vm, 1);
      vlib_process_get_events (vm, NULL);

      /* process ske child sas */
      ske_main_per_thread_data_t *tkm;
      vec_foreach (tkm, km->per_thread_data)
      {
	ske_sa_t *sa;
        /* *INDENT-OFF* */
        pool_foreach (sa, tkm->sas, ({
          ske_child_sa_t *c;
          vec_foreach (c, sa->childs)
            {
            req_sent |= ske_mngr_process_child_sa(sa, c);
            }
        }));
        /* *INDENT-ON* */
      }

      /* process ipsec sas */
      ipsec_sa_t *sa;
      /* *INDENT-OFF* */
      pool_foreach (sa, im->sad, ({
        ske_mngr_process_ipsec_sa(sa);
      }));
      /* *INDENT-ON* */

      if (req_sent)
	{
	  vlib_process_wait_for_event_or_clock (vm, 5);
	  vlib_process_get_events (vm, NULL);
	  req_sent = 0;
	}

    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ske_mngr_process_node, static) = {
    .function = ske_mngr_process_fn,
    .type = VLIB_NODE_TYPE_PROCESS,
    .name =
    "ske-manager-process",
};

VLIB_PLUGIN_REGISTER () = {
    .version = VPP_BUILD_VER,
    .description = "SGX-based Key Exchange (SKE) Protocol",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
