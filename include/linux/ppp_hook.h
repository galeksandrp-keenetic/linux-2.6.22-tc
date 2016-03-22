#ifndef _PPP_HOOK_H_
#define _PPP_HOOK_H_

#include <linux/types.h>

struct ppp_channel;
struct net_device;

extern int (*ppp_chan_stats_switch_get_hook)(struct ppp_channel *chan);

extern void (*ppp_stat_add_tx_hook)(struct ppp_channel *chan, u32 add_pkt,
				    u32 add_bytes);

extern void (*ppp_stat_add_rx_hook)(struct ppp_channel *chan, u32 add_pkt,
				    u32 add_bytes);

extern int (*ppp_stats_switch_get_hook)(struct net_device *dev);

extern void (*ppp_stats_switch_set_hook)(struct net_device *dev, int on);

extern void (*ppp_stats_update_hook)(struct net_device *dev,
				     u32 rx_bytes, u32 rx_packets,
				     u32 tx_bytes, u32 tx_packets);
#endif
