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

#include <ctype.h>

#include <vnet/vnet.h>
#include <vnet/api_errno.h>
#include <vnet/ip/ip.h>
#include <vnet/interface.h>

#include <vnet/ipsec/ipsec.h>
#include <plugins/ske/ske.h>
#include <plugins/ske/ske_priv.h>

/* *INDENT-OFF* */
typedef CLIB_PACKED (struct {
  u8 nextpayload;
  u8 flags;
  u16 length;
  u8 protocol_id;
  u8 spi_size;
  u16 msg_type;
  u8 payload[0];
}) ske_notify_payload_header_t;
/* *INDENT-ON* */

/* *INDENT-OFF* */
typedef CLIB_PACKED (struct {
  u8 ts_type;
  u8 protocol_id;
  u16 selector_len;
  u16 start_port;
  u16 end_port;
  ip4_address_t start_addr;
  ip4_address_t end_addr;
}) ske_ts_payload_entry_t;
/* *INDENT-OFF* */

/* *INDENT-OFF* */
typedef CLIB_PACKED (struct {
  u8 nextpayload;
  u8 flags;
  u16 length;
  u8 num_ts;
  u8 reserved[3];
  ske_ts_payload_entry_t ts[0];
}) ske_ts_payload_header_t;
/* *INDENT-OFF* */

/* *INDENT-OFF* */
typedef CLIB_PACKED (struct {
  u8 last_or_more;
  u8 reserved;
  u16 proposal_len;
  u8 proposal_num;
  u8 protocol_id;
  u8 spi_size;
  u8 num_transforms; u32 spi[0];
}) ske_sa_proposal_data_t;
/* *INDENT-OFF* */

/* *INDENT-OFF* */
typedef CLIB_PACKED (struct {
  u8 last_or_more;
  u8 reserved;
  u16 transform_len;
  u8 transform_type;
  u8 reserved2;
  u16 transform_id;
  u8 attributes[0];
}) ske_sa_transform_data_t;
/* *INDENT-OFF* */

/* *INDENT-OFF* */
typedef CLIB_PACKED (struct {
  u8 nextpayload;
  u8 flags;
  u16 length;
  u8 protocol_id;
  u8 spi_size;
  u16 num_of_spi;
  u32 spi[0];
}) ske_delete_payload_header_t;
/* *INDENT-OFF* */

static ske_payload_header_t *
ske_payload_add_hdr (ske_payload_chain_t * c, u8 payload_type, int len)
{
  ske_payload_header_t *hdr =
    (ske_payload_header_t *) & c->data[c->last_hdr_off];
  u8 *tmp;

  if (c->data)
    hdr->nextpayload = payload_type;
  else
    c->first_payload_type = payload_type;

  c->last_hdr_off = vec_len (c->data);
  vec_add2 (c->data, tmp, len);
  hdr = (ske_payload_header_t *) tmp;
  clib_memset (hdr, 0, len);

  hdr->length = clib_host_to_net_u16 (len);

  return hdr;
}

static void
ske_payload_add_data (ske_payload_chain_t * c, u8 * data)
{
  u16 len;
  ske_payload_header_t *hdr;

  vec_append (c->data, data);
  hdr = (ske_payload_header_t *) & c->data[c->last_hdr_off];
  len = clib_net_to_host_u16 (hdr->length);
  hdr->length = clib_host_to_net_u16 (len + vec_len (data));
}

void
ske_payload_add_notify (ske_payload_chain_t * c, u16 msg_type, u8 * data)
{
  ske_payload_add_notify_2(c, msg_type, data, 0);
}

void
ske_payload_add_notify_2 (ske_payload_chain_t * c, u16 msg_type,
                               u8 * data, ske_notify_t * notify)
{
  ske_notify_payload_header_t *n;

  n =
    (ske_notify_payload_header_t *) ske_payload_add_hdr (c,
                                                           SKE_PAYLOAD_NOTIFY,
                                                           sizeof (*n));
  n->msg_type = clib_host_to_net_u16 (msg_type);
  if (notify)
    {
      n->protocol_id = notify->protocol_id;
      if (notify->spi)
        {
          n->spi_size = 4;
        }
    }
  ske_payload_add_data (c, data);
}

void
ske_payload_add_sa (ske_payload_chain_t * c,
		      ske_sa_proposal_t * proposals)
{
  ske_payload_header_t *ph;
  ske_sa_proposal_data_t *prop;
  ske_sa_transform_data_t *tr;
  ske_sa_proposal_t *p;
  ske_sa_transform_t *t;

  u8 *tmp;
  u8 *pr_data = 0;
  u8 *tr_data = 0;

  ske_payload_add_hdr (c, SKE_PAYLOAD_SA, sizeof (*ph));

  vec_foreach (p, proposals)
  {
    int spi_size = (p->protocol_id == SKE_PROTOCOL_ESP) ? 4 : 0;
    pr_data = vec_new (u8, sizeof (ske_sa_proposal_data_t) + spi_size);
    prop = (ske_sa_proposal_data_t *) pr_data;
    prop->last_or_more = proposals - p + 1 < vec_len (proposals) ? 2 : 0;
    prop->protocol_id = p->protocol_id;
    prop->proposal_num = p->proposal_num;
    prop->spi_size = spi_size;
    prop->num_transforms = vec_len (p->transforms);

    if (spi_size)
      prop->spi[0] = clib_host_to_net_u32 (p->spi);

    DBG_PLD ("proposal num %u protocol_id %u last_or_more %u spi_size %u%s%U",
	     prop->proposal_num, prop->protocol_id, prop->last_or_more,
	     prop->spi_size, prop->spi_size ? " spi_data " : "",
	     format_hex_bytes, prop->spi, prop->spi_size);

    vec_foreach (t, p->transforms)
    {
      vec_add2 (tr_data, tmp, sizeof (*tr) + vec_len (t->attrs));
      tr = (ske_sa_transform_data_t *) tmp;
      tr->last_or_more =
	((t - p->transforms) + 1 < vec_len (p->transforms)) ? 3 : 0;
      tr->transform_type = t->type;
      tr->transform_id = clib_host_to_net_u16 (t->transform_id);
      tr->transform_len =
	clib_host_to_net_u16 (sizeof (*tr) + vec_len (t->attrs));

      if (vec_len (t->attrs) > 0)
	clib_memcpy_fast (tr->attributes, t->attrs, vec_len (t->attrs));

      DBG_PLD
	("transform type %U transform_id %u last_or_more %u attr_size %u%s%U",
	 format_ske_transform_type, tr->transform_type, t->transform_id,
	 tr->last_or_more, vec_len (t->attrs),
	 vec_len (t->attrs) ? " attrs " : "", format_hex_bytes,
	 tr->attributes, vec_len (t->attrs));
    }

    prop->proposal_len =
      clib_host_to_net_u16 (vec_len (tr_data) + vec_len (pr_data));
    ske_payload_add_data (c, pr_data);
    ske_payload_add_data (c, tr_data);
    vec_free (pr_data);
    vec_free (tr_data);
  }
}

void
ske_payload_add_ke (ske_payload_chain_t * c, u16 dh_group, u8 * dh_data)
{
  ske_ke_payload_header_t *ke;
  ke = (ske_ke_payload_header_t *) ske_payload_add_hdr (c, SKE_PAYLOAD_KE,
							  sizeof (*ke));

  ke->dh_group = clib_host_to_net_u16 (dh_group);
  ske_payload_add_data (c, dh_data);
}

void
ske_payload_add_nonce (ske_payload_chain_t * c, u8 * nonce)
{
  ske_payload_add_hdr (c, SKE_PAYLOAD_NONCE,
			 sizeof (ske_payload_header_t));
  ske_payload_add_data (c, nonce);
}

void
ske_payload_add_id (ske_payload_chain_t * c, ske_id_t * id, u8 type)
{
  ske_id_payload_header_t *idp;
  idp =
    (ske_id_payload_header_t *) ske_payload_add_hdr (c, type,
						       sizeof (*idp));

  idp->id_type = id->type;
  ske_payload_add_data (c, id->data);
}

void
ske_payload_add_delete (ske_payload_chain_t * c, ske_delete_t * d)
{
  ske_delete_payload_header_t *dp;
  u16 num_of_spi = vec_len (d);
  ske_delete_t *d2;
  dp =
    (ske_delete_payload_header_t *) ske_payload_add_hdr (c,
							   SKE_PAYLOAD_DELETE,
							   sizeof (*dp));

  if (d[0].protocol_id == SKE_PROTOCOL_IKE)
    {
      dp->protocol_id = 1;
    }
  else
    {
      dp->protocol_id = d[0].protocol_id;
      dp->spi_size = 4;
      dp->num_of_spi = clib_host_to_net_u16 (num_of_spi);
      vec_foreach (d2, d)
      {
	u8 *data = vec_new (u8, 4);
	u32 spi = clib_host_to_net_u32 (d2->spi);
	clib_memcpy (data, &spi, 4);
	ske_payload_add_data (c, data);
	vec_free (data);
      }
    }
}

void
ske_payload_add_auth (ske_payload_chain_t * c, ske_auth_t * auth)
{
  ske_auth_payload_header_t *ap;
  ap =
    (ske_auth_payload_header_t *) ske_payload_add_hdr (c,
							 SKE_PAYLOAD_AUTH,
							 sizeof (*ap));

  ap->auth_method = auth->method;
  ske_payload_add_data (c, auth->data);
}

void
ske_payload_add_ts (ske_payload_chain_t * c, ske_ts_t * ts, u8 type)
{
  ske_ts_payload_header_t *tsh;
  ske_ts_t *ts2;
  u8 *data = 0, *tmp;

  tsh =
    (ske_ts_payload_header_t *) ske_payload_add_hdr (c, type,
						       sizeof (*tsh));
  tsh->num_ts = vec_len (ts);

  vec_foreach (ts2, ts)
  {
    ASSERT (ts2->ts_type == 7);	/*TS_IPV4_ADDR_RANGE */
    ske_ts_payload_entry_t *entry;
    vec_add2 (data, tmp, sizeof (*entry));
    entry = (ske_ts_payload_entry_t *) tmp;
    entry->ts_type = ts2->ts_type;
    entry->protocol_id = ts2->protocol_id;
    entry->selector_len = clib_host_to_net_u16 (16);
    entry->start_port = clib_host_to_net_u16 (ts2->start_port);
    entry->end_port = clib_host_to_net_u16 (ts2->end_port);
    entry->start_addr.as_u32 = ts2->start_addr.as_u32;
    entry->end_addr.as_u32 = ts2->end_addr.as_u32;
  }

  ske_payload_add_data (c, data);
  vec_free (data);
}

void
ske_payload_chain_add_padding (ske_payload_chain_t * c, int bs)
{
  u8 *tmp __attribute__ ((unused));
  u8 pad_len = (vec_len (c->data) / bs + 1) * bs - vec_len (c->data);
  vec_add2 (c->data, tmp, pad_len);
  c->data[vec_len (c->data) - 1] = pad_len - 1;
}

ske_sa_proposal_t *
ske_parse_sa_payload (ske_payload_header_t * skep)
{
  ske_sa_proposal_t *v = 0;
  ske_sa_proposal_t *proposal;
  ske_sa_transform_t *transform;

  u32 plen = clib_net_to_host_u16 (skep->length);

  ske_sa_proposal_data_t *sap;
  int proposal_ptr = 0;

  do
    {
      sap = (ske_sa_proposal_data_t *) & skep->payload[proposal_ptr];
      int i;
      int transform_ptr;

      DBG_PLD ("proposal num %u len %u last_or_more %u id %u "
	       "spi_size %u num_transforms %u",
	       sap->proposal_num, clib_net_to_host_u16 (sap->proposal_len),
	       sap->last_or_more, sap->protocol_id, sap->spi_size,
	       sap->num_transforms);

      /* IKE proposal should not have SPI */
      if (sap->protocol_id == SKE_PROTOCOL_IKE && sap->spi_size != 0)
	goto data_corrupted;

      /* IKE proposal should not have SPI */
      if (sap->protocol_id == SKE_PROTOCOL_ESP && sap->spi_size != 4)
	goto data_corrupted;

      transform_ptr = proposal_ptr + sizeof (*sap) + sap->spi_size;

      vec_add2 (v, proposal, 1);
      proposal->proposal_num = sap->proposal_num;
      proposal->protocol_id = sap->protocol_id;

      if (sap->spi_size == 4)
	{
	  proposal->spi = clib_net_to_host_u32 (sap->spi[0]);
	}

      for (i = 0; i < sap->num_transforms; i++)
	{
	  ske_sa_transform_data_t *tr =
	    (ske_sa_transform_data_t *) & skep->payload[transform_ptr];
	  u16 tlen = clib_net_to_host_u16 (tr->transform_len);

	  if (tlen < sizeof (*tr))
	    goto data_corrupted;

	  vec_add2 (proposal->transforms, transform, 1);

	  transform->type = tr->transform_type;
	  transform->transform_id = clib_net_to_host_u16 (tr->transform_id);
	  if (tlen > sizeof (*tr))
	    vec_add (transform->attrs, tr->attributes, tlen - sizeof (*tr));

	  DBG_PLD
	    ("transform num %u len %u last_or_more %u type %U id %u%s%U", i,
	     tlen, tr->last_or_more, format_ske_sa_transform, transform,
	     clib_net_to_host_u16 (tr->transform_id),
	     tlen > sizeof (*tr) ? " attrs " : "", format_hex_bytes,
	     tr->attributes, tlen - sizeof (*tr));

	  transform_ptr += tlen;
	}

      proposal_ptr += clib_net_to_host_u16 (sap->proposal_len);
    }
  while (proposal_ptr < (plen - sizeof (*skep)) && sap->last_or_more == 2);

  /* data validation */
  if (proposal_ptr != (plen - sizeof (*skep)) || sap->last_or_more)
    goto data_corrupted;

  return v;

data_corrupted:
  DBG_PLD ("SA payload data corrupted");
  ske_sa_free_proposal_vector (&v);
  return 0;
}

ske_ts_t *
ske_parse_ts_payload (ske_payload_header_t * skep)
{
  ske_ts_payload_header_t *tsp = (ske_ts_payload_header_t *) skep;
  ske_ts_t *r = 0, *ts;
  u8 i;

  for (i = 0; i < tsp->num_ts; i++)
    {
      if (tsp->ts[i].ts_type != 7)	/*  TS_IPV4_ADDR_RANGE */
	{
	  DBG_PLD ("unsupported TS type received (%u)", tsp->ts[i].ts_type);
	  continue;
	}

      vec_add2 (r, ts, 1);
      ts->ts_type = tsp->ts[i].ts_type;
      ts->protocol_id = tsp->ts[i].protocol_id;
      ts->start_port = tsp->ts[i].start_port;
      ts->end_port = tsp->ts[i].end_port;
      ts->start_addr.as_u32 = tsp->ts[i].start_addr.as_u32;
      ts->end_addr.as_u32 = tsp->ts[i].end_addr.as_u32;
    }
  return r;
}

ske_notify_t *
ske_parse_notify_payload (ske_payload_header_t * skep)
{
  ske_notify_payload_header_t *n = (ske_notify_payload_header_t *) skep;
  u32 plen = clib_net_to_host_u16 (skep->length);
  ske_notify_t *r = 0;
  u32 spi;

  DBG_PLD ("msg_type %U len %u%s%U",
	   format_ske_notify_msg_type, clib_net_to_host_u16 (n->msg_type),
	   plen, plen > sizeof (*n) ? " data " : "",
	   format_hex_bytes, n->payload, plen - sizeof (*n));

  r = vec_new (ske_notify_t, 1);
  r->msg_type = clib_net_to_host_u16 (n->msg_type);
  r->protocol_id = n->protocol_id;

  if (n->spi_size == 4)
    {
      clib_memcpy (&spi, n->payload, n->spi_size);
      r->spi = clib_net_to_host_u32 (spi);
      DBG_PLD ("spi %lx", r->spi);
    }
  else if (n->spi_size == 0)
    {
      r->spi = 0;
    }
  else
    {
      clib_warning ("invalid SPI Size %d", n->spi_size);
    }

  if (plen > (sizeof (*n) + n->spi_size))
    {
      vec_add (r->data, n->payload + n->spi_size,
	       plen - sizeof (*n) - n->spi_size);
    }

  return r;
}

void
ske_parse_vendor_payload (ske_payload_header_t * skep)
{
  u32 plen = clib_net_to_host_u16 (skep->length);
  int i;
  int is_string = 1;

  for (i = 0; i < plen - 4; i++)
    if (!isprint (skep->payload[i]))
      is_string = 0;

  DBG_PLD ("len %u data %s:%U",
	   plen,
	   is_string ? "string" : "hex",
	   is_string ? format_ascii_bytes : format_hex_bytes,
	   skep->payload, plen - sizeof (*skep));
}

ske_delete_t *
ske_parse_delete_payload (ske_payload_header_t * skep)
{
  ske_delete_payload_header_t *d = (ske_delete_payload_header_t *) skep;
  u32 plen = clib_net_to_host_u16 (skep->length);
  ske_delete_t *r = 0, *del;
  u16 num_of_spi = clib_net_to_host_u16 (d->num_of_spi);
  u16 i = 0;

  DBG_PLD ("protocol_id %u spi_size %u num_of_spi %u len %u%s%U",
	   d->protocol_id, d->spi_size, num_of_spi,
	   plen, plen > sizeof (d) ? " data " : "",
	   format_hex_bytes, d->spi, plen - sizeof (*d));

  if (d->protocol_id == SKE_PROTOCOL_IKE)
    {
      r = vec_new (ske_delete_t, 1);
      r->protocol_id = 1;
    }
  else
    {
      r = vec_new (ske_delete_t, num_of_spi);
      vec_foreach (del, r)
      {
	del->protocol_id = d->protocol_id;
	del->spi = clib_net_to_host_u32 (d->spi[i++]);
      }
    }

  return r;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
