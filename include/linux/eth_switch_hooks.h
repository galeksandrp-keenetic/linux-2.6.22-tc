#ifndef __INCLUDE_LINUX_ETH_SWITCH_HOOKS_H
#define __INCLUDE_LINUX_ETH_SWITCH_HOOKS_H

#include <linux/types.h>

struct net_device;

typedef bool eth_switch_iface_fn(const struct net_device *const dev);

typedef int eth_switch_map_mc_mac_fn(const struct net_device *const dev,
				     const u8 *const uc_mac,
				     const u8 *const mc_mac);

typedef int eth_switch_unmap_mc_mac_fn(const struct net_device *const dev,
				       const u8 *const uc_mac,
				       const u8 *const mc_mac);

typedef int eth_switch_set_wan_port_fn(const unsigned char port);

#define ETH_SWITCH_DEFINE_HOOK(name)					\
eth_switch_##name##_fn *eth_switch_##name##_hook_get(void);		\
void eth_switch_##name##_hook_put(void);				\
void eth_switch_##name##_hook_set(eth_switch_##name##_fn *name##_hook);	\
void eth_switch_##name##_hook_unset(void)

ETH_SWITCH_DEFINE_HOOK(iface);
ETH_SWITCH_DEFINE_HOOK(map_mc_mac);
ETH_SWITCH_DEFINE_HOOK(unmap_mc_mac);
ETH_SWITCH_DEFINE_HOOK(set_wan_port);

#endif /* __INCLUDE_LINUX_ETH_SWITCH_HOOKS_H */

