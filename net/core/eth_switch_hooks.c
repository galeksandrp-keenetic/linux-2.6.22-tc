#include <linux/module.h>
#include <linux/delay.h>
#include <linux/eth_switch_hooks.h>

#define ETH_SWITCH_DECLARE_HOOK(name)					\
static eth_switch_##name##_fn *eth_switch_##name##_hook = NULL;		\
static int eth_switch_##name##_use = 0;					\
static DEFINE_SPINLOCK(eth_switch_##name##_lock);			\
									\
eth_switch_##name##_fn *eth_switch_##name##_hook_get(void)		\
{									\
	eth_switch_##name##_fn *hook = NULL;				\
	spin_lock_bh(&eth_switch_##name##_lock);			\
	if (eth_switch_##name##_use > 0) {				\
		hook = eth_switch_##name##_hook;			\
		eth_switch_##name##_use ++;				\
	}								\
	spin_unlock_bh(&eth_switch_##name##_lock);			\
	return hook;							\
}									\
EXPORT_SYMBOL(eth_switch_##name##_hook_get);				\
									\
void eth_switch_##name##_hook_put(void)					\
{									\
	spin_lock_bh(&eth_switch_##name##_lock);			\
	eth_switch_##name##_use--;					\
	spin_unlock_bh(&eth_switch_##name##_lock);			\
}									\
EXPORT_SYMBOL(eth_switch_##name##_hook_put);				\
									\
void eth_switch_##name##_hook_set(eth_switch_##name##_fn *name##_hook)	\
{									\
	spin_lock_bh(&eth_switch_##name##_lock);			\
	if (eth_switch_##name##_use <= 0) {				\
		eth_switch_##name##_hook = name##_hook;			\
		eth_switch_##name##_use = 1;				\
	}								\
	spin_unlock_bh(&eth_switch_##name##_lock);			\
}									\
EXPORT_SYMBOL(eth_switch_##name##_hook_set);				\
									\
void eth_switch_##name##_hook_unset(void)				\
{									\
	spin_lock_bh(&eth_switch_##name##_lock);			\
	eth_switch_##name##_use--;					\
	spin_unlock_bh(&eth_switch_##name##_lock);			\
									\
	do {								\
		spin_lock_bh(&eth_switch_##name##_lock);		\
		if (eth_switch_##name##_use <= 0) {			\
			eth_switch_##name##_hook = NULL;		\
			eth_switch_##name##_use = 0;			\
			spin_unlock_bh(&eth_switch_##name##_lock);	\
			break;						\
		}							\
		spin_unlock_bh(&eth_switch_##name##_lock);		\
		udelay(10);						\
	} while (1);							\
}									\
EXPORT_SYMBOL(eth_switch_##name##_hook_unset)


ETH_SWITCH_DECLARE_HOOK(iface);
ETH_SWITCH_DECLARE_HOOK(map_mc_mac);
ETH_SWITCH_DECLARE_HOOK(unmap_mc_mac);
ETH_SWITCH_DECLARE_HOOK(set_wan_port);

