#ifndef _PPP_SESSION_H
#define _PPP_SESSION_H

#include <linux/if.h>
#include <linux/list.h>

extern spinlock_t pppoe_sessions_lock;
extern struct list_head pppoe_sessions;

struct pppoe_session_item {
        struct list_head list;
        int idx;
        int sid;
        char name[IFNAMSIZ];
};

#endif
