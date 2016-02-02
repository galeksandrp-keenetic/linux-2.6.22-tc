#include <linux/module.h>
#include <linux/ntc_shaper_hooks.h>

rwlock_t ntc_shaper_lock = __RW_LOCK_UNLOCKED(ntc_shaper_lock);
EXPORT_SYMBOL(ntc_shaper_lock);

ntc_shaper_hook_fn *ntc_shaper_ingress_hook = NULL;
EXPORT_SYMBOL(ntc_shaper_ingress_hook);

ntc_shaper_hook_fn *ntc_shaper_egress_hook = NULL;
EXPORT_SYMBOL(ntc_shaper_egress_hook);

