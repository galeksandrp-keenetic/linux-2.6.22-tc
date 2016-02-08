/*
 *	Linux ethernet bridge
 *
 *	Authors:
 *	Lennert Buytenhek		<buytenh@gnu.org>
 *
 *	$Id: if_bridge.h,v 1.4 2010/06/25 11:37:52 xhshi Exp $
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */

#ifndef _LINUX_IF_BRIDGE_H
#define _LINUX_IF_BRIDGE_H

#include <linux/types.h>

#define SYSFS_BRIDGE_ATTR	"bridge"
#define SYSFS_BRIDGE_FDB	"brforward"
#define SYSFS_BRIDGE_PORT_SUBDIR "brif"
#define SYSFS_BRIDGE_PORT_ATTR	"brport"
#define SYSFS_BRIDGE_PORT_LINK	"bridge"

#define BRCTL_VERSION 1

#define BRCTL_GET_VERSION 0
#define BRCTL_GET_BRIDGES 1
#define BRCTL_ADD_BRIDGE 2
#define BRCTL_DEL_BRIDGE 3
#define BRCTL_ADD_IF 4
#define BRCTL_DEL_IF 5
#define BRCTL_GET_BRIDGE_INFO 6
#define BRCTL_GET_PORT_LIST 7
#define BRCTL_SET_BRIDGE_FORWARD_DELAY 8
#define BRCTL_SET_BRIDGE_HELLO_TIME 9
#define BRCTL_SET_BRIDGE_MAX_AGE 10
#define BRCTL_SET_AGEING_TIME 11
#define BRCTL_SET_GC_INTERVAL 12
#define BRCTL_GET_PORT_INFO 13
#define BRCTL_SET_BRIDGE_STP_STATE 14
#define BRCTL_SET_BRIDGE_PRIORITY 15
#define BRCTL_SET_PORT_PRIORITY 16
#define BRCTL_SET_PATH_COST 17
#define BRCTL_GET_FDB_ENTRIES 18
#ifdef CONFIG_IGMP_SNOOPING
/*IGMP Snooping*/
#define BRCTL_SET_IGMPSNOOPING_STATE 19
#define BRCTL_SET_IGMPSNOOPING_AGEING_TIME 20
#define BRCTL_GET_MC_FDB_ENTRIES 21
#define BRCTL_SET_IGMPSNOOPING_QUICKLEAVE 22
#define BRCTL_SET_IGMPSNOOPING_DBG 23
#define BRCTL_SET_IGMPSNOOPING_ROUTEPORTFLAG 27
#endif
#ifdef CONFIG_MLD_SNOOPING
/*MLD Snooping*/
#define BRCTL_SET_MLDSNOOPING_STATE 24
#define BRCTL_SET_MLDSNOOPING_AGE 25
#define BRCTL_GET_MLDSNOOPING_INFO 26
#endif

#define BR_STATE_DISABLED 0
#define BR_STATE_LISTENING 1
#define BR_STATE_LEARNING 2
#define BR_STATE_FORWARDING 3
#define BR_STATE_BLOCKING 4

struct __bridge_info
{
	__u64 designated_root;
	__u64 bridge_id;
	__u32 root_path_cost;
	__u32 max_age;
	__u32 hello_time;
	__u32 forward_delay;
	__u32 bridge_max_age;
	__u32 bridge_hello_time;
	__u32 bridge_forward_delay;
	__u8 topology_change;
	__u8 topology_change_detected;
	__u8 root_port;
	__u8 stp_enabled;
	__u32 ageing_time;
	__u32 gc_interval;
	__u32 hello_timer_value;
	__u32 tcn_timer_value;
	__u32 topology_change_timer_value;
	__u32 gc_timer_value;
#ifdef CONFIG_IGMP_SNOOPING
	__u8 igmpsnoop_enabled;
	__u8 igmpsnoop_quickleave;
	__u8 igmpsnoop_routeportflag;
	__u8 igmpsnoop_dbg;
	__u32 igmpsnoop_ageing_time;
#endif
};

struct __port_info
{
	__u64 designated_root;
	__u64 designated_bridge;
	__u16 port_id;
	__u16 designated_port;
	__u32 path_cost;
	__u32 designated_cost;
	__u8 state;
	__u8 top_change_ack;
	__u8 config_pending;
	__u8 unused0;
	__u32 message_age_timer_value;
	__u32 forward_delay_timer_value;
	__u32 hold_timer_value;
#ifdef CONFIG_IGMP_SNOOPING
	__u8 is_router;
#endif
};

struct __fdb_entry
{
	__u8 mac_addr[6];
	__u8 port_no;
	__u8 is_local;
	__u32 ageing_timer_value;
	__u32 unused;
};
#ifdef CONFIG_IGMP_SNOOPING
struct __mc_fdb_entry
{
	__u8 group_addr[16];
	__u8 host_addr[6];
	__u16 port_no;
	__u32 ageing_timer_value;
	#ifdef CONFIG_TCSUPPORT_IGMP_SNOOPING_V3
	__u8 src_addr[16];
	__u8 filter_mode;
	#endif
	__u32 unused;
};
#endif

#ifdef __KERNEL__

#include <linux/netdevice.h>

extern void brioctl_set(int (*ioctl_hook)(unsigned int, void __user *));
extern struct sk_buff *(*br_handle_frame_hook)(struct net_bridge_port *p,
					       struct sk_buff *skb);
extern int (*br_should_route_hook)(struct sk_buff **pskb);
extern void ubrioctl_set(int (*ioctl_hook)(unsigned int, void __user *));

#endif

#endif
