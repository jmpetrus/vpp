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
/*
 * client.h: dhcp client
 */

#ifndef included_dhcp_client_h
#define included_dhcp_client_h

#include <vnet/ip/ip.h>
#include <dhcp/dhcp4_packet.h>

#define foreach_dhcp_client_state               \
_(DHCP_DISCOVER)                                \
_(DHCP_REQUEST)                                 \
_(DHCP_BOUND)

typedef enum
{
#define _(a) a,
  foreach_dhcp_client_state
#undef _
} dhcp_client_state_t;

struct dhcp_client_t_;

/**
 * Callback function for DHCP complete events
 */
typedef void (*dhcp_event_cb_t) (u32 client_index,
				 const struct dhcp_client_t_ * client);

typedef struct dhcp_client_t_
{
  dhcp_client_state_t state;

  /* the interface in question */
  u32 sw_if_index;

  /* State machine retry counter */
  u32 retry_count;

  /* Send next pkt at this time */
  f64 next_transmit;
  f64 lease_expires;

  /* DHCP transaction ID, a random number */
  u32 transaction_id;

  /* leased address, other learned info DHCP */
  ip4_address_t leased_address;	/* from your_ip_address field */
  ip4_address_t dhcp_server;
  u32 subnet_mask_width;	/* option 1 */
  ip4_address_t router_address;	/* option 3 */
  ip4_address_t *domain_server_address;	/* option 6 */
  u32 lease_renewal_interval;	/* option 51 */
  u32 lease_lifetime;		/* option 59 */

  /* Requested data (option 55) */
  u8 *option_55_data;

  /* hostname and software client identifiers */
  u8 *hostname;
  u8 *client_identifier;	/* software version, e.g. vpe 1.0 */

  /* Information used for event callback */
  u32 client_index;
  u32 pid;

  /* Set the broadcast Flag in the Discover/Request messages */
  u8 set_broadcast_flag;
  /* Interface MAC address, so we can do an rx-packet-for-us check */
  u8 client_hardware_address[6];
  u8 client_detect_feature_enabled;

  /* the unicast adjacency for the DHCP server */
  adj_index_t ai_ucast;
  /* the broadcast adjacency on the link */
  adj_index_t ai_bcast;
  /* IP DSCP to set in sent packets */
  ip_dscp_t dscp;

  dhcp_event_cb_t event_callback;
} dhcp_client_t;

typedef struct
{
  /* DHCP client pool */
  dhcp_client_t *clients;
  uword *client_by_sw_if_index;
  u32 seed;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
} dhcp_client_main_t;

typedef struct
{
  int is_add;
  u32 sw_if_index;
  u8 set_broadcast_flag;

  /* vectors, consumed by dhcp client code */
  u8 *hostname;
  u8 *client_identifier;

  /* Bytes containing requested option numbers */
  u8 *option_55_data;

  /* Information used for event callback */
  u32 client_index;
  u32 pid;
  ip_dscp_t dscp;
  dhcp_event_cb_t event_callback;
} dhcp_client_add_del_args_t;

extern dhcp_client_main_t dhcp_client_main;

#define EVENT_DHCP_CLIENT_WAKEUP	1

int dhcp_client_for_us (u32 bi0,
			vlib_buffer_t * b0,
			ip4_header_t * ip0,
			udp_header_t * u0, dhcp_header_t * dh0);

/**
 * Add/Delete DHCP clients
 */
extern int dhcp_client_config (u32 is_add,
			       u32 client_index,
			       vlib_main_t * vm,
			       u32 sw_if_index,
			       u8 * hostname,
			       u8 * client_id,
			       dhcp_event_cb_t event_callback,
			       u8 set_broadcast_flag,
			       ip_dscp_t dscp, u32 pid);

/**
 * callback function for clients walking the DHCP client configurations
 *
 * @param client The client being visitsed
 * @param data   The data passed during the call to 'walk'
 * @return !0 to continue walking 0 to stop.
 */
typedef int (*dhcp_client_walk_cb_t) (const dhcp_client_t * client,
				      void *data);

/**
 * Walk (visit each) DHCP client configuration
 *
 * @param cb The callback function invoked as each client is visited
 * @param ctx Context data passed back to the client in the invocation of
 *             the callback.
 */
extern void dhcp_client_walk (dhcp_client_walk_cb_t cb, void *ctx);

#endif /* included_dhcp_client_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
