#include <linux/module.h>
#include <linux/types.h>

struct ppp_channel;
struct net_device;

int (*ppp_chan_stats_switch_get_hook)(struct ppp_channel *chan) = NULL;
EXPORT_SYMBOL(ppp_chan_stats_switch_get_hook);

void (*ppp_stat_add_tx_hook)(struct ppp_channel *chan, u32 add_pkt,
			     u32 add_bytes) = NULL;
EXPORT_SYMBOL(ppp_stat_add_tx_hook);

void (*ppp_stat_add_rx_hook)(struct ppp_channel *chan, u32 add_pkt,
			     u32 add_bytes) = NULL;
EXPORT_SYMBOL(ppp_stat_add_rx_hook);

int (*ppp_stats_switch_get_hook)(struct net_device *dev) = NULL;
EXPORT_SYMBOL(ppp_stats_switch_get_hook);

void (*ppp_stats_switch_set_hook)(struct net_device *dev, int on) = NULL;
EXPORT_SYMBOL(ppp_stats_switch_set_hook);

void (*ppp_stats_update_hook)(struct net_device *dev,
			      u32 rx_bytes, u32 rx_packets,
			      u32 tx_bytes, u32 tx_packets) = NULL;
EXPORT_SYMBOL(ppp_stats_update_hook);
