/*
 * mpls_output.c: MPLS Adj rewrite
 *
 * Copyright (c) 2012-2014 Cisco and/or its affiliates.
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
#include <vnet/pg/pg.h>
#include <vnet/ip/ip.h>
#include <vnet/mpls/mpls.h>
#include <vnet/ip/ip_frag.h>

typedef struct {
  /* Adjacency taken. */
  u32 adj_index;
  u32 flow_hash;
} mpls_output_trace_t;

typedef enum {
  MPLS_OUTPUT_MODE,
  MPLS_OUTPUT_MIDCHAIN_MODE
}mpls_output_mode_t;

#define foreach_mpls_output_next        	\
_(DROP, "error-drop")                           \
_(IP4_FRAG, "ip4-frag")                         \
_(IP6_FRAG, "ip6-frag")

typedef enum {
#define _(s,n) MPLS_OUTPUT_NEXT_##s,
  foreach_mpls_output_next
#undef _
  MPLS_OUTPUT_N_NEXT,
} mpls_output_next_t;

static u8 *
format_mpls_output_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  mpls_output_trace_t * t = va_arg (*args, mpls_output_trace_t *);

  s = format (s, "adj-idx %d : %U flow hash: 0x%08x",
              t->adj_index,
              format_ip_adjacency, t->adj_index, FORMAT_IP_ADJACENCY_NONE,
	      t->flow_hash);
  return s;
}

/*
 * Save the mpls header length and adjust the current to ip header
 */
static inline u32
set_mpls_fragmentation(vlib_buffer_t * p0, ip_adjacency_t * adj0)
{
  u32 next0;

  /* advance size of (all) mpls header to ip header before fragmenting */
  /* save the current pointing to first mpls header. */
  vnet_buffer (p0)->mpls.mpls_hdr_length = vnet_buffer(p0)->l3_hdr_offset - p0->current_data;
  vlib_buffer_advance (p0, vnet_buffer (p0)->mpls.mpls_hdr_length);

  /* IP fragmentation */
  ip_frag_set_vnet_buffer (p0, adj0[0].rewrite_header.max_l3_packet_bytes,
                           IP4_FRAG_NEXT_MPLS_OUTPUT,
                           ((vnet_buffer (p0)->mpls.pyld_proto == DPO_PROTO_IP4) ? IP_FRAG_FLAG_IP4_HEADER:IP_FRAG_FLAG_IP6_HEADER));

  /* Tell ip_frag to retain certain mpls parameters after fragmentation of mpls packet */
  vnet_buffer (p0)->ip_frag.flags = (vnet_buffer (p0)->ip_frag.flags | IP_FRAG_FLAG_MPLS_HEADER);
  next0 = (vnet_buffer (p0)->mpls.pyld_proto == DPO_PROTO_IP4)? MPLS_OUTPUT_NEXT_IP4_FRAG:MPLS_OUTPUT_NEXT_IP6_FRAG;

  return next0;
}

static inline uword
mpls_output_inline (vlib_main_t * vm,
                    vlib_node_runtime_t * node,
                    vlib_frame_t * from_frame,
                    mpls_output_mode_t mode)
{
  u32 n_left_from, next_index, * from, * to_next, thread_index;
  vlib_node_runtime_t * error_node;
  u32 n_left_to_next;
  mpls_main_t *mm;

  thread_index = vlib_get_thread_index();
  error_node = vlib_node_get_runtime (vm, mpls_output_node.index);
  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;
  next_index = node->cached_next_index;
  mm = &mpls_main;

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index,
                           to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
        {
          ip_adjacency_t * adj0;
          mpls_unicast_header_t *hdr0;
          vlib_buffer_t * p0;
          u32 pi0, adj_index0, next0, error0;
          word rw_len0;

          ip_adjacency_t * adj1;
          mpls_unicast_header_t *hdr1;
          vlib_buffer_t * p1;
          u32 pi1, adj_index1, next1, error1;
          word rw_len1;

          /* Prefetch next iteration. */
          {
            vlib_buffer_t * p2, * p3;

            p2 = vlib_get_buffer (vm, from[2]);
            p3 = vlib_get_buffer (vm, from[3]);

            vlib_prefetch_buffer_header (p2, STORE);
            vlib_prefetch_buffer_header (p3, STORE);

            CLIB_PREFETCH (p2->data, sizeof (hdr0[0]), STORE);
            CLIB_PREFETCH (p3->data, sizeof (hdr1[0]), STORE);
          }

          pi0 = to_next[0] = from[0];
          pi1 = to_next[1] = from[1];

          from += 2;
          n_left_from -= 2;
          to_next += 2;
          n_left_to_next -= 2;

          p0 = vlib_get_buffer (vm, pi0);
          p1 = vlib_get_buffer (vm, pi1);

          adj_index0 = vnet_buffer (p0)->ip.adj_index[VLIB_TX];
          adj_index1 = vnet_buffer (p1)->ip.adj_index[VLIB_TX];

          adj0 = adj_get(adj_index0);
          adj1 = adj_get(adj_index1);
          hdr0 = vlib_buffer_get_current (p0);
          hdr1 = vlib_buffer_get_current (p1);

          /* Guess we are only writing on simple Ethernet header. */
          vnet_rewrite_two_headers (adj0[0], adj1[0], hdr0, hdr1,
                                   sizeof (ethernet_header_t));

          /* Update packet buffer attributes/set output interface. */
          rw_len0 = adj0[0].rewrite_header.data_bytes;
          rw_len1 = adj1[0].rewrite_header.data_bytes;
	  vnet_buffer (p0)->mpls.save_rewrite_length = rw_len0;
	  vnet_buffer (p1)->mpls.save_rewrite_length = rw_len1;

          /* Bump the adj counters for packet and bytes */
          vlib_increment_combined_counter
              (&adjacency_counters,
               thread_index,
               adj_index0,
               1,
               vlib_buffer_length_in_chain (vm, p0) + rw_len0);
          vlib_increment_combined_counter
              (&adjacency_counters,
               thread_index,
               adj_index1,
               1,
               vlib_buffer_length_in_chain (vm, p1) + rw_len1);

          /* Check MTU of outgoing interface. */
          if (PREDICT_TRUE(vlib_buffer_length_in_chain (vm, p0) <=
                           adj0[0].rewrite_header.max_l3_packet_bytes))
            {
              vlib_buffer_advance(p0, -rw_len0);

              vnet_buffer (p0)->sw_if_index[VLIB_TX] =
                  adj0[0].rewrite_header.sw_if_index;
              next0 = adj0[0].rewrite_header.next_index;
              error0 = IP4_ERROR_NONE;

              if (PREDICT_FALSE(adj0[0].rewrite_header.flags & VNET_REWRITE_HAS_FEATURES))
                vnet_feature_arc_start (mm->output_feature_arc_index,
                                        adj0[0].rewrite_header.sw_if_index,
                                        &next0, p0);
            }
          else
            {
	      error0 = IP4_ERROR_MTU_EXCEEDED;
	      next0 = set_mpls_fragmentation (p0, adj0);
              vlib_node_increment_counter (vm, mpls_output_node.index,
                                           MPLS_ERROR_PKTS_NEED_FRAG,
                                           1);
            }
          if (PREDICT_TRUE(vlib_buffer_length_in_chain (vm, p1) <=
                           adj1[0].rewrite_header.max_l3_packet_bytes))
            {
              vlib_buffer_advance(p1, -rw_len1);

              vnet_buffer (p1)->sw_if_index[VLIB_TX] =
                  adj1[0].rewrite_header.sw_if_index;
              next1 = adj1[0].rewrite_header.next_index;
              error1 = IP4_ERROR_NONE;

              if (PREDICT_FALSE(adj1[0].rewrite_header.flags & VNET_REWRITE_HAS_FEATURES))
                vnet_feature_arc_start (mm->output_feature_arc_index,
                                        adj1[0].rewrite_header.sw_if_index,
                                        &next1, p1);
            }
          else
            {
	      error1 = IP4_ERROR_MTU_EXCEEDED;
	      next1 = set_mpls_fragmentation (p1, adj1);
              vlib_node_increment_counter (vm, mpls_output_node.index,
                                           MPLS_ERROR_PKTS_NEED_FRAG,
                                           1);
            }
          if (mode == MPLS_OUTPUT_MIDCHAIN_MODE)
          {
	      adj0->sub_type.midchain.fixup_func
                (vm, adj0, p0,
                 adj0->sub_type.midchain.fixup_data);
	      adj1->sub_type.midchain.fixup_func
                (vm, adj1, p1,
                 adj1->sub_type.midchain.fixup_data);
          }

          p0->error = error_node->errors[error0];
          p1->error = error_node->errors[error1];

          if (PREDICT_FALSE(p0->flags & VLIB_BUFFER_IS_TRACED))
            {
              mpls_output_trace_t *tr = vlib_add_trace (vm, node,
                                                        p0, sizeof (*tr));
              tr->adj_index = vnet_buffer(p0)->ip.adj_index[VLIB_TX];
              tr->flow_hash = vnet_buffer(p0)->ip.flow_hash;
            }
          if (PREDICT_FALSE(p1->flags & VLIB_BUFFER_IS_TRACED))
            {
              mpls_output_trace_t *tr = vlib_add_trace (vm, node,
                                                        p1, sizeof (*tr));
              tr->adj_index = vnet_buffer(p1)->ip.adj_index[VLIB_TX];
              tr->flow_hash = vnet_buffer(p1)->ip.flow_hash;
            }

          vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
                                           to_next, n_left_to_next,
                                           pi0, pi1, next0, next1);
        }

      while (n_left_from > 0 && n_left_to_next > 0)
        {
	  ip_adjacency_t * adj0;
	  mpls_unicast_header_t *hdr0;
	  vlib_buffer_t * p0;
	  u32 pi0, adj_index0, next0, error0;
          word rw_len0;

	  pi0 = to_next[0] = from[0];

	  p0 = vlib_get_buffer (vm, pi0);

	  adj_index0 = vnet_buffer (p0)->ip.adj_index[VLIB_TX];

	  adj0 = adj_get(adj_index0);
	  hdr0 = vlib_buffer_get_current (p0);

	  /* Guess we are only writing on simple Ethernet header. */
          vnet_rewrite_one_header (adj0[0], hdr0, 
                                   sizeof (ethernet_header_t));
          
          /* Update packet buffer attributes/set output interface. */
          rw_len0 = adj0[0].rewrite_header.data_bytes;
          vnet_buffer (p0)->mpls.save_rewrite_length = rw_len0;

          vlib_increment_combined_counter
              (&adjacency_counters,
               thread_index,
               adj_index0,
               1,
               vlib_buffer_length_in_chain (vm, p0) + rw_len0);

          /* Check MTU of outgoing interface. */
          if (PREDICT_TRUE(vlib_buffer_length_in_chain (vm, p0) <=
                           adj0[0].rewrite_header.max_l3_packet_bytes))
            {
              vlib_buffer_advance(p0, -rw_len0);

              vnet_buffer (p0)->sw_if_index[VLIB_TX] =
                  adj0[0].rewrite_header.sw_if_index;
              next0 = adj0[0].rewrite_header.next_index;
              error0 = IP4_ERROR_NONE;

              if (PREDICT_FALSE(adj0[0].rewrite_header.flags & VNET_REWRITE_HAS_FEATURES))
                vnet_feature_arc_start (mm->output_feature_arc_index,
                                        adj0[0].rewrite_header.sw_if_index,
                                        &next0, p0);
            }
          else
            {
	      error0 = IP4_ERROR_MTU_EXCEEDED;
	      next0 = set_mpls_fragmentation (p0, adj0);
              vlib_node_increment_counter (vm, mpls_output_node.index,
                                           MPLS_ERROR_PKTS_NEED_FRAG,
                                           1);
            }
          if (mode == MPLS_OUTPUT_MIDCHAIN_MODE)
          {
	      adj0->sub_type.midchain.fixup_func
                (vm, adj0, p0,
                 adj0->sub_type.midchain.fixup_data);
          }

          p0->error = error_node->errors[error0];

	  from += 1;
	  n_left_from -= 1;
	  to_next += 1;
	  n_left_to_next -= 1;
      
          if (PREDICT_FALSE(p0->flags & VLIB_BUFFER_IS_TRACED)) 
            {
              mpls_output_trace_t *tr = vlib_add_trace (vm, node, 
                                                        p0, sizeof (*tr));
              tr->adj_index = vnet_buffer(p0)->ip.adj_index[VLIB_TX];
              tr->flow_hash = vnet_buffer(p0)->ip.flow_hash;
            }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   pi0, next0);
        }

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  vlib_node_increment_counter (vm, mpls_output_node.index,
                               MPLS_ERROR_PKTS_ENCAP,
                               from_frame->n_vectors);

  return from_frame->n_vectors;
}

static char * mpls_error_strings[] = {
#define mpls_error(n,s) s,
#include "error.def"
#undef mpls_error
};

VLIB_NODE_FN (mpls_output_node) (vlib_main_t * vm,
             vlib_node_runtime_t * node,
             vlib_frame_t * from_frame)
{
    return (mpls_output_inline(vm, node, from_frame, MPLS_OUTPUT_MODE));
}

VLIB_REGISTER_NODE (mpls_output_node) = {
  .name = "mpls-output",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),
  .n_errors = MPLS_N_ERROR,
  .error_strings = mpls_error_strings,

  .n_next_nodes = MPLS_OUTPUT_N_NEXT,
  .next_nodes = {
#define _(s,n) [MPLS_OUTPUT_NEXT_##s] = n,
    foreach_mpls_output_next
#undef _
  },

  .format_trace = format_mpls_output_trace,
};

VLIB_NODE_FN (mpls_midchain_node) (vlib_main_t * vm,
               vlib_node_runtime_t * node,
               vlib_frame_t * from_frame)
{
    return (mpls_output_inline(vm, node, from_frame, MPLS_OUTPUT_MIDCHAIN_MODE));
}

VLIB_REGISTER_NODE (mpls_midchain_node) = {
  .name = "mpls-midchain",
  .vector_size = sizeof (u32),

  .format_trace = format_mpls_output_trace,

  .sibling_of = "mpls-output",
};

/**
 * @brief Next index values from the MPLS incomplete adj node
 */
#define foreach_mpls_adj_incomplete_next       	\
_(DROP, "error-drop")                   \
_(IP4,  "ip4-arp")                      \
_(IP6,  "ip6-discover-neighbor")

typedef enum {
#define _(s,n) MPLS_ADJ_INCOMPLETE_NEXT_##s,
  foreach_mpls_adj_incomplete_next
#undef _
  MPLS_ADJ_INCOMPLETE_N_NEXT,
} mpls_adj_incomplete_next_t;

/**
 * @brief A struct to hold tracing information for the MPLS label imposition
 * node.
 */
typedef struct mpls_adj_incomplete_trace_t_
{
    u32 next;
} mpls_adj_incomplete_trace_t;


/**
 * @brief Graph node for incomplete MPLS adjacency.
 * This node will push traffic to either the v4-arp or v6-nd node
 * based on the next-hop proto of the adj.
 * We pay a cost for this 'routing' node, but an incomplete adj is the
 * exception case.
 */
VLIB_NODE_FN (mpls_adj_incomplete_node) (vlib_main_t * vm,
                     vlib_node_runtime_t * node,
                     vlib_frame_t * from_frame)
{
    u32 n_left_from, next_index, * from, * to_next;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index,
                           to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
        {
          u32 pi0, next0, adj_index0;
	  ip_adjacency_t * adj0;
	  vlib_buffer_t * p0;

 	  pi0 = to_next[0] = from[0];
	  p0 = vlib_get_buffer (vm, pi0);
	  from += 1;
	  n_left_from -= 1;
	  to_next += 1;
	  n_left_to_next -= 1;

          adj_index0 = vnet_buffer (p0)->ip.adj_index[VLIB_TX];

	  adj0 = adj_get(adj_index0);

          if (PREDICT_TRUE(FIB_PROTOCOL_IP4 == adj0->ia_nh_proto))
          {
              next0 = MPLS_ADJ_INCOMPLETE_NEXT_IP4;
          }
          else
          {
              next0 = MPLS_ADJ_INCOMPLETE_NEXT_IP6;
          }              

	  if (PREDICT_FALSE(p0->flags & VLIB_BUFFER_IS_TRACED)) 
	  {
	      mpls_adj_incomplete_trace_t *tr =
		  vlib_add_trace (vm, node, p0, sizeof (*tr));
	      tr->next = next0;
	  }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   pi0, next0);
        }

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return from_frame->n_vectors;
}

static u8 *
format_mpls_adj_incomplete_trace (u8 * s, va_list * args)
{
    CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
    CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
    mpls_adj_incomplete_trace_t * t;
    u32 indent;

    t = va_arg (*args, mpls_adj_incomplete_trace_t *);
    indent = format_get_indent (s);

    s = format (s, "%Unext:%d",
                format_white_space, indent,
                t->next);
    return (s);
}

VLIB_REGISTER_NODE (mpls_adj_incomplete_node) = {
  .name = "mpls-adj-incomplete",
  .format_trace = format_mpls_adj_incomplete_trace,
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),
  .n_errors = MPLS_N_ERROR,
  .error_strings = mpls_error_strings,

  .n_next_nodes = MPLS_ADJ_INCOMPLETE_N_NEXT,
  .next_nodes = {
#define _(s,n) [MPLS_ADJ_INCOMPLETE_NEXT_##s] = n,
    foreach_mpls_adj_incomplete_next
#undef _
  },
};

