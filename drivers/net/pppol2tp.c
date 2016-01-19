/*****************************************************************************
 * Linux PPP over L2TP (PPPoX/PPPoL2TP) Sockets
 *
 * PPPoX    --- Generic PPP encapsulation socket family
 * PPPoL2TP --- PPP over L2TP (RFC 2661)
 *
 *
 * Version:    1.0
 *
*/

#ifndef AUTOCONF_INCLUDED
#include <linux/config.h>
#endif
#include <linux/module.h>
#include <linux/version.h>
#include <linux/string.h>
#include <linux/list.h>
#include <asm/uaccess.h>

#include <linux/kernel.h>
#include <linux/spinlock.h>
#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/seq_file.h>
#include <linux/errno.h>

#include <linux/netdevice.h>
#include <linux/net.h>
#include <linux/inetdevice.h>
#include <linux/skbuff.h>
#include <linux/init.h>
#include <linux/udp.h>
#include <linux/if_pppox.h>
#include <linux/if_pppol2tp.h>
#include <net/sock.h>
#include <linux/ppp_channel.h>
#include <linux/ppp_defs.h>
#include <linux/if_ppp.h>
#include <linux/file.h>
#include <linux/hash.h>
#include <linux/proc_fs.h>
#include <net/dst.h>
#include <net/ip.h>
#include <net/udp.h>
#include <net/xfrm.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>


#include <asm/byteorder.h>
#include <asm/atomic.h>

#if defined(CONFIG_RA_HW_NAT) || defined(CONFIG_RA_HW_NAT_MODULE)
#include <linux/../../net/nat/hw_nat/ra_nat.h>
#endif

extern int (*vpn_pthrough)(struct sk_buff *skb, int in);
extern int (*vpn_pthrough_setup)(uint32_t sip, int add);

static struct proc_dir_entry *proc_cmd = NULL;

//#define L2TP_USE_UDP_CKSUM

#define PPPOL2TP_DRV_VERSION	"1.04"

/* L2TP header constants */
#define L2TP_HDRFLAG_T	   0x8000
#define L2TP_HDRFLAG_L	   0x4000
#define L2TP_HDRFLAG_S	   0x0800
#define L2TP_HDRFLAG_O	   0x0200
#define L2TP_HDRFLAG_P	   0x0100
#define L2TP_HDR_VER_MASK  0x000F
#define L2TP_HDR_VER	   0x0002
#define PPPOL2TP_L2TP_HDR_SIZE 	6
#define PPPOL2TP_L2TP_HDR_SIZE_ZLB 	12

#define SK_STATE(sk) (sk)->sk_state

typedef struct l2tp_sess {
	struct l2tp_sess *pnext;
	struct pppol2tp_addr l2a;
	struct sock *sk;
	uint32_t magic;
	uint16_t remns;
	uint16_t remnr;
} L2TP_SESS, *PL2TP_SESS;

PL2TP_SESS pses_head = NULL, pses_tail = NULL;
static spinlock_t lock_chan;
static atomic_t chan_cnt;

PL2TP_SESS l2tp_find_src(uint16_t sid, uint16_t tid) {
	PL2TP_SESS pses;

	switch( atomic_read(&chan_cnt) ) {
	case 0: return NULL;
	case 1: return (pses_head->l2a.s_session == sid && pses_head->l2a.s_tunnel == tid) ? pses_head : NULL;
	default: break;
	}
	
	spin_lock_bh(&lock_chan);
	pses = pses_head;
	while( pses ) 
		if( pses->l2a.s_session == sid && pses->l2a.s_tunnel == tid ) break;
		else pses = pses->pnext;
	spin_unlock_bh(&lock_chan);
	return pses;
}

PL2TP_SESS l2tp_find_src_tid(uint16_t tid) {
	PL2TP_SESS pses;

	switch( atomic_read(&chan_cnt) ) {
	case 0: return NULL;
	case 1: return (pses_head->l2a.s_tunnel == tid) ? pses_head : NULL;
	default: break;
	}
	
	spin_lock_bh(&lock_chan);
	pses = pses_head;
	while( pses ) 
		if( pses->l2a.s_tunnel == tid ) break;
		else pses = pses->pnext;
	spin_unlock_bh(&lock_chan);
	return pses;
}


inline PL2TP_SESS l2tp_find_dst(struct sock *sk) {
	return (PL2TP_SESS)sk->sk_user_data;
}

PL2TP_SESS l2tp_add(struct pppol2tp_addr *pl2a, struct sock *sk) {
	PL2TP_SESS pses;
	int (*vsetup)(uint32_t sip, int add);

	if( !(pses = (PL2TP_SESS)kmalloc(sizeof(L2TP_SESS), GFP_KERNEL)) ) return NULL;
	memset(pses, 0, sizeof(*pses));
	pses->l2a = *pl2a;
	pses->sk = sk;

	spin_lock_bh(&lock_chan);
	if( !pses_head ) pses_head = pses_tail = pses;
	else pses_tail = pses_tail->pnext = pses;
	
	sk->sk_user_data = (void *)pses;
	
	if( (vsetup = rcu_dereference(vpn_pthrough_setup)) ) 
		vsetup(pses->l2a.addr.sin_addr.s_addr, 1);
	
	spin_unlock_bh(&lock_chan);

	atomic_add(1, &chan_cnt);
	
	return pses;
}

int l2tp_del(struct sock *sk) {
	PL2TP_SESS pses, *pps;
	int (*vsetup)(uint32_t sip, int add);

	spin_lock_bh(&lock_chan);
	pps = &pses_head;
	while( (pses = *pps) ) {
		if( pses->sk == sk ) {
			 atomic_sub(1, &chan_cnt);
			if( pses == pses_tail ) {
				if( pses == pses_head ) pses_head = pses_tail = NULL;
				else pses_tail = (PL2TP_SESS)pps;
		}
	   	 *pps = pses->pnext;

	   	 if( (vsetup = rcu_dereference(vpn_pthrough_setup)) ) 
				vsetup(pses->l2a.addr.sin_addr.s_addr, 0);
	   	 
	   	 kfree(pses);
	   	 sk->sk_user_data = NULL;
	   	 break;
		} else pps = &pses->pnext;
	}
	spin_unlock_bh(&lock_chan);
	return (pses ? 1 : 0);
}

#ifdef L2TP_USE_UDP_CKSUM
unsigned short udp_cksum(u_int32_t sa, u_int32_t da, unsigned short *addr, int len) {
	register int sum    = 0;
	u_short answer      = 0;
	register u_short *w;
	register int nleft;
	
	struct pseudohdr  {
	    u_int32_t source_address;
       u_int32_t dest_address;
       u_int8_t  place_holder;
       u_int8_t  protocol;
       u_int16_t length;
   } pshdr = {
  		sa, da, 0, 17, htons(len)
   };
   
   nleft = sizeof(pshdr);
   w = (unsigned short *)&pshdr;
   
   while (nleft > 1)  {
		sum += *w++;
		nleft -= 2;
	}

	w = addr;
	nleft  = len;
	while (nleft > 1)  {
		sum += *w++;
		nleft -= 2;
	}

	if (nleft == 1) {
		*(u_char *)(&answer) = *(u_char *)w ;
		sum += answer;
	}

	sum = (sum >> 16) + (sum & 0xffff);     /* add hi 16 to low 16 */
	sum += (sum >> 16);                     /* add carry */
	answer = ~sum;                          /* truncate to 16 bits */
	return(answer);
}
#endif
	
static inline void pppol2tp_build_l2tp_header(PL2TP_SESS pses, void *buf) {
	u16 *bufp = buf;

	*bufp++ = htons(L2TP_HDR_VER);
	*bufp++ = htons(pses->l2a.d_tunnel);
	*bufp++ = htons(pses->l2a.d_session);
}

	

static inline void l2tp_xmit_dev(PL2TP_SESS pses, struct sock *sk, struct sk_buff *skb, struct rtable *rt) {
	struct udphdr *uh;
	struct iphdr  *iph;
	u16 udp_len;
	int (*vhook)(struct sk_buff *skb, int in);

	if( !rt ) {
		struct flowi fl = { 
			.oif = 0,
			.nl_u = { 
				.ip4_u = { 
					.saddr = pses->l2a.bind_addr.sin_addr.s_addr,
					.daddr = pses->l2a.addr.sin_addr.s_addr,
					.tos = RT_TOS(0) 
				} 
			},
			.proto = IPPROTO_UDP 
		};
		if( ip_route_output_key(&rt, &fl) ) {
			goto tx_error;
		}
	}

	udp_len = sizeof(struct udphdr) + skb->len;
	
	uh = (struct udphdr *)skb_push(skb, sizeof(*uh));
	skb_reset_transport_header(skb);
	
	uh->source = htons(1701);
	uh->dest = htons(1701);
	uh->len = htons(udp_len);
	uh->check = 0;
#ifdef L2TP_USE_UDP_CKSUM
	uh->check = udp_cksum(rt->rt_src, rt->rt_dst, (void *)uh, htons(uh->len));
#endif

	memset(&(IPCB(skb)->opt), 0, sizeof(IPCB(skb)->opt));
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,16)
	IPCB(skb)->flags &= ~(IPSKB_XFRM_TUNNEL_SIZE | IPSKB_XFRM_TRANSFORMED |
			      IPSKB_REROUTED);
#endif

	iph = (struct iphdr*)skb_push(skb, sizeof(*iph));
	skb_reset_network_header(skb);

	iph->version	= 4;
	iph->ihl			= sizeof(struct iphdr) >> 2;
   if (ip_dont_fragment(sk, &rt->u.dst)) iph->frag_off = htons(IP_DF);
   else iph->frag_off = 0;
	iph->protocol	= IPPROTO_UDP;
	iph->tos			=	0;
	iph->daddr		=	rt->rt_dst;
	iph->saddr		=	rt->rt_src;
	iph->ttl 		= dst_metric(&rt->u.dst, RTAX_HOPLIMIT);
	iph->tot_len 	= htons(skb->len);

	dst_release(skb->dst);
	skb->dst = &rt->u.dst;

	nf_reset(skb);

	skb->ip_summed = CHECKSUM_NONE;
	ip_select_ident_more(iph, &rt->u.dst, sk, (skb_shinfo(skb)->gso_segs ?: 1) - 1);
	ip_send_check(iph);

#if defined(CONFIG_RA_HW_NAT) || defined(CONFIG_RA_HW_NAT_MODULE)
	FOE_ALG_SKIP(skb);
#endif

	if( !(vhook = rcu_dereference(vpn_pthrough)) || !vhook(skb, 2) ) {
		NF_HOOK(PF_INET, NF_IP_LOCAL_OUT, skb, NULL, rt->u.dst.dev, dst_output);
	}

	return;
	
tx_error:
	if( skb ) kfree_skb(skb);
}
	
static int l2tp_xmit(struct ppp_channel *chan, struct sk_buff *skb) {
	static const u8 ppph[2] = { 0xff, 0x03 };
 	struct sock *sk = (struct sock *) chan->private;
	int error;
	u16 *ptr;
	int headroom;
	PL2TP_SESS pses;
	struct sk_buff *new_skb;
	struct rtable *rt;

	if( sock_flag(sk, SOCK_DEAD) || 
		 !(sk->sk_state & PPPOX_CONNECTED) ||
		 !(pses = l2tp_find_dst(sk)) ) {
		error = -ENOTCONN;
		goto end;
	}

	{
		struct flowi fl = { 
			.oif = 0,
			.nl_u = { 
				.ip4_u = { 
					.saddr = pses->l2a.bind_addr.sin_addr.s_addr,
					.daddr = pses->l2a.addr.sin_addr.s_addr,
					.tos = RT_TOS(0) 
				} 
			},
			.proto = IPPROTO_UDP 
		};
		if( ip_route_output_key(&rt, &fl) ) {
			goto end;
		}
	}

	headroom = LL_RESERVED_SPACE(rt->u.dst.dev) + sizeof(struct iphdr) + sizeof(struct udphdr) + PPPOL2TP_L2TP_HDR_SIZE + sizeof(ppph);

	if( skb_headroom(skb) < headroom || skb_shared(skb) || skb_cloned(skb) ) {
		new_skb = skb_realloc_headroom(skb, headroom);
	
		if (!new_skb) {
			ip_rt_put(rt);
		goto end;
	}

		if (skb->sk) skb_set_owner_w(new_skb, skb->sk);
		kfree_skb(skb);
		skb = new_skb;
	}

	skb_push(skb, sizeof(ppph));
	skb->data[0] = ppph[0];
	skb->data[1] = ppph[1];
	
	ptr = (u16 *)skb_push(skb, PPPOL2TP_L2TP_HDR_SIZE);
	*ptr++ = htons(L2TP_HDR_VER);
	*ptr++ = htons(pses->l2a.d_tunnel);
	*ptr++ = htons(pses->l2a.d_session);
	
	l2tp_xmit_dev(pses, sk, skb, rt);
	return 1;
end:
	if( skb ) kfree_skb(skb);

	return 1;
}

extern void ppp_stat_add(struct ppp_channel *chan, struct sk_buff *skb);

int l2tp_input(struct sk_buff *skb) {
	struct iphdr *iph;
	u8 *ptr, *psh;
	u16 hdrflags, tid, sid, offset, nr, ns, hlen, len, plen;
	PL2TP_SESS pses;
	struct sock *sk;
	struct pppox_sock *po;

	if( atomic_read(&chan_cnt) ) {
		if( !pskb_may_pull(skb, 14) ) goto skip;

		iph = ip_hdr(skb);
		ptr = psh = (u8 *)((char *)iph + iph->ihl * 4 + sizeof(struct udphdr));

		hdrflags = ntohs(*(u16*)ptr);
	  	ptr += 2;
		
		if( hdrflags & L2TP_HDRFLAG_L ) {
			hlen = ntohs(*(u16*)ptr);
			ptr += 2;
		}

		tid = ntohs(*(u16 *) ptr);
		ptr += 2;
		sid = ntohs(*(u16 *) ptr);
		ptr += 2;

		if( hdrflags & L2TP_HDRFLAG_T ) {
			if( !(pses = l2tp_find_src_tid(tid)) || (iph->saddr != pses->l2a.addr.sin_addr.s_addr) ) goto skip;
		} else {
			if( !(pses = l2tp_find_src(sid, tid)) || (iph->saddr != pses->l2a.addr.sin_addr.s_addr) ) goto skip;
		}

		sk = pses->sk;
		sock_hold(sk);
		
		if( !(sk->sk_state & PPPOX_CONNECTED) || sock_flag(sk, SOCK_DEAD) ) goto skip_put;

		
		if( hdrflags & L2TP_HDRFLAG_S ) {
     		ns = ntohs(*(u16 *) ptr);
			ptr += 2;
			nr = ntohs(*(u16 *) ptr);
			ptr += 2;
		} else {
			ns = nr = 0;
		}

		if( hdrflags & L2TP_HDRFLAG_O ) ptr += 2 + ntohs(*(u16 *) ptr);
			offset = (int)(ptr - psh) + iph->ihl * 4 + sizeof(struct udphdr) ;
	
      if( hdrflags & L2TP_HDRFLAG_T ) { /* control packet, process hello and send to userspace */
     		if( !(hdrflags & L2TP_HDRFLAG_S) || !pskb_may_pull(skb, offset + 8) ) goto skip_put;

     		ptr += 6;
     		if( ntohs(*(u16 *) ptr) != 0x6 ) goto skip_put; /* check hello avp type */
     		
     		/* build zlb */
     		skb_pull(skb, (iph->ihl * 4 + sizeof(struct udphdr))); /* l2tp header len */
     		*((u16 *) psh) = htons(L2TP_HDRFLAG_T | L2TP_HDRFLAG_L | L2TP_HDRFLAG_S |  L2TP_HDR_VER);
     		psh += 2;
     		*((u16 *) psh) = htons(PPPOL2TP_L2TP_HDR_SIZE_ZLB);
     		psh += 2;
			*((u16 *) psh) = htons(pses->l2a.d_tunnel);
			psh += 2;
			*((u16 *) psh) = 0;
			psh += 2;
			*((u16 *) psh) = htons(nr);
			psh += 2;
			*((u16 *) psh) = htons(ns + 1);
			psh += 2;
			
			skb_trim(skb, PPPOL2TP_L2TP_HDR_SIZE_ZLB);
			
			pses->remns = ns + 1;
			pses->remnr = nr;
			
			l2tp_xmit_dev(pses, sk, skb, NULL);
			} else {
     		if( !pskb_may_pull(skb, offset + 2) ) goto skip_put; /* data packet failed to parse, back to stack */

     		dst_release(skb->dst);
			skb->dst = NULL;
			nf_reset(skb);
	
#if defined(CONFIG_RA_HW_NAT) || defined(CONFIG_RA_HW_NAT_MODULE)
				FOE_ALG_SKIP(skb);
#endif
			   skb->ip_summed = CHECKSUM_NONE;
			   

				po = pppox_sk(sk);
				skb_pull(skb, offset);

				if ((skb->data[0] == 0xff) && (skb->data[1] == 0x03))
					skb_pull(skb, 2);

				if ((*skb->data) & 1){
					/* protocol is compressed */
					skb_push(skb, 1)[0] = 0;
				}

				if( skb->len >= 2 && 
					 skb->data[0] == 0x00 &&
					 skb->data[1] == 0x21 ) {

					skb_pull(skb, 2);

					skb_reset_mac_header(skb);
					skb_reset_network_header(skb);
					skb_reset_transport_header(skb);

					ppp_stat_add(&po->chan, skb);

					netif_rx(skb);
				} else {
					if( !pses->magic &&
						 skb->len >= 10 && 
						 skb->data[0] == 0xc0 &&
						 skb->data[1] == 0x21 &&
						 skb->data[2] == 0x2 && /* configuration ack */
						 skb->data[3] == 0x1 ) { /* request id */

						 len = htons( *((u16*)&skb->data[4]) );
						 ptr = &skb->data[6];

						 if( len > skb->len - 6 ) len = skb->len - 6;

						 while( len > 0 ) {
							if( *ptr == 0x5 || *ptr == 0 )	break;
							else {
								plen = *(ptr + 1);
								if( plen <= len ) {
									ptr += plen;
									len -= plen;
								} else break;
							}
						 }

						 if( *ptr == 0x5 ) 
							 pses->magic = ntohl(*((u32*)&ptr[2]));
					}

					/* lcp echo request */
					 if( pses->magic  &&
						  skb->len >= 10 && 
						  skb->data[0] == 0xc0 &&
						  skb->data[1] == 0x21 &&
						  skb->data[2] == 0x9 ) {

						 skb->data[2] = 0xa;				 
						 *((u32*)&skb->data[6]) = htonl(pses->magic);

						 l2tp_xmit(&po->chan, skb);
					 } else {
						 skb_set_network_header(skb, skb->head - skb->data);
						 ppp_input(&po->chan, skb);
					 }
				}
			}

			sock_put(sk);
			return 1;
	}

skip:
	return 0;

skip_put:
	sock_put(sk);	
	return 0;
}

EXPORT_SYMBOL(l2tp_input);

int l2tp_read_cmd(char *pdata, char **pstart, off_t uoff, int icount, int *pieof, void *pref) {
	int iread;
	char *pst;
	PL2TP_SESS pses;
                     
   if( uoff > 0 ) {
     *pieof = 1;
     return 0;
   }
   
   pst = pdata;
   *pdata = 0;
   
   spin_lock_bh(&lock_chan);
	pses = pses_head;
	while( pses && icount > 0 ) {
		iread = snprintf(pdata, icount - 1, "%d,%d,%d,%d\n", pses->l2a.s_session, pses->l2a.s_tunnel, pses->remns, pses->remnr);
		
		icount -= iread;
  		pdata  += iread;
  		*pdata = 0;

		pses = pses->pnext;
	}
	spin_unlock_bh(&lock_chan);
   
   return (int)(pdata - pst);
}                               

static int l2tp_getname(struct socket *sock, struct sockaddr *uaddr,
			    int *usockaddr_len, int peer)
{
	int len = sizeof(struct sockaddr_pppol2tp);
	struct sockaddr_pppol2tp sp;
	struct sock *sk = sock->sk;
	PL2TP_SESS pses;
	int error = 0;

	error = -ENOTCONN;
	if( sk->sk_state != PPPOX_CONNECTED ||
		 !(pses = l2tp_find_dst(sk)) )
				goto end;

	sp.sa_family	= AF_PPPOX;
	sp.sa_protocol	= PX_PROTO_OL2TP;
	memcpy(&sp.pppol2tp, &pses->l2a, sizeof(struct pppol2tp_addr));
	memcpy(uaddr, &sp, len);
	*usockaddr_len = len;

	error = 0;
end:

	return error;
}


static struct ppp_channel_ops l2tp_chan_ops= {
	.start_xmit = l2tp_xmit,
//	.ioctl = pppox_ioctl
};

int l2tp_connect(struct socket *sock, struct sockaddr *uservaddr, int sockaddr_len, int flags) {
	struct sock *sk = sock->sk;
	struct sockaddr_pppol2tp *sp = (struct sockaddr_pppol2tp *) uservaddr;
	struct pppox_sock *po = pppox_sk(sk);
	struct rtable *rt;
	int err;
	PL2TP_SESS pses;

	lock_sock(sk);

	if( sp->sa_protocol != PX_PROTO_OL2TP ||
		 (sk->sk_state & PPPOX_CONNECTED) ||
		 (sp->pppol2tp.s_tunnel == 0)
	  ) {
		release_sock(sk);
		return -EINVAL;
	}

	if( !(pses = l2tp_add(&sp->pppol2tp, sk)) ) {
		release_sock(sk);
		return -EINVAL;
	}

	po->chan.private = sk;
	po->chan.ops = &l2tp_chan_ops;

		{
		struct flowi fl = {
			.oif = 0,
			.nl_u = { 
				.ip4_u = { 
					.saddr = pses->l2a.bind_addr.sin_addr.s_addr,
					.daddr = pses->l2a.addr.sin_addr.s_addr,
					.tos = RT_TOS(0) 
	}
		  		  	  },
			.proto = IPPROTO_UDP 
		};

		security_sk_classify_flow(sk, &fl);
		if (ip_route_output_key(&rt, &fl)) {
			err = -EHOSTUNREACH;
			l2tp_del(sk);
			release_sock(sk);
	return err;
	}

		sk_setup_caps(sk, &rt->u.dst);
	}

	po->chan.mtu = dst_mtu(&rt->u.dst);
	ip_rt_put(rt);
	
	if( !po->chan.mtu ) po->chan.mtu = PPP_MTU;
	po->chan.mtu -= (sizeof(struct iphdr) + sizeof(struct udphdr) + PPPOL2TP_L2TP_HDR_SIZE + 2);
	po->chan.hdrlen = LL_MAX_HEADER + sizeof(struct iphdr) + sizeof(struct udphdr) + PPPOL2TP_L2TP_HDR_SIZE + 2;

	if( (err = ppp_register_channel(&po->chan)) ) {
		l2tp_del(sk);
	release_sock(sk);
	return err;
	}

	sk->sk_state = PPPOX_CONNECTED;
	release_sock(sk);

	return 0;
}

static int l2tp_release(struct socket *sock) {
	struct sock *sk = sock->sk;

	if( !sk ) return 0;

	lock_sock(sk);	

	if( sock_flag(sk, SOCK_DEAD) ) {
		release_sock(sk);
		return -EBADF;
	}

	pppox_unbind_sock(sk);

	l2tp_del(sk);

	sk->sk_state = PPPOX_DEAD;
	sock_orphan(sk);
	sock->sk = NULL;

	release_sock(sk);
	sock_put(sk);

	return 0;
}

static void l2tp_destruct(struct sock *sk) {
    if( !(SK_STATE(sk) & PPPOX_DEAD) ) {
   	 l2tp_del(sk);
	    pppox_unbind_sock(sk);
	}
    skb_queue_purge(&sk->sk_receive_queue);
}

static struct proto l2tp_sk_proto = {
	.name	  		= "PPPOL2TP",
	.owner	  	= THIS_MODULE,
	.obj_size 	= sizeof(struct pppox_sock),
};

static struct proto_ops l2tp_ops = {
	.family		= AF_PPPOX,
	.owner		= THIS_MODULE,
	.release		= l2tp_release,
	.connect		= l2tp_connect,
	.getname		= l2tp_getname,
   .setsockopt	= sock_no_setsockopt,
   .getsockopt	= sock_no_getsockopt,
	.bind		= sock_no_bind,
	.socketpair	= sock_no_socketpair,
	.accept		= sock_no_accept,
	.poll			= sock_no_poll,
	.listen		= sock_no_listen,
	.shutdown	= sock_no_shutdown,
	.sendmsg		= sock_no_sendmsg,
   .recvmsg		= sock_no_recvmsg,
	.mmap		= sock_no_mmap,
	.ioctl		= pppox_ioctl,
};

/* no packet's here, interface  */
static int l2tp_recv_none(struct sock *sk, struct sk_buff *skb) {
	kfree_skb(skb);
	return NET_RX_DROP;
}

static int l2tp_create(struct socket *sock) {
	struct sock *sk;
	
	if( !(sk = sk_alloc(PF_PPPOX, GFP_KERNEL, &l2tp_sk_proto, 1)) ) return -ENOMEM;
	
	sock_init_data(sock, sk);
	
	sock->state  = SS_UNCONNECTED;
	sock->ops    = &l2tp_ops;
	
	sk->sk_backlog_rcv = l2tp_recv_none;
	sk->sk_protocol    = PX_PROTO_OL2TP;
	sk->sk_family      = PF_PPPOX;
	sk->sk_state       = PPPOX_NONE;
	sk->sk_type        = SOCK_STREAM;
	sk->sk_destruct    = l2tp_destruct;
	
	return 0;
}

static struct pppox_proto l2tp_proto = {
	.create		= l2tp_create,
	.owner		= THIS_MODULE,
};


static int __init l2tp_init(void) {
	int err;

	atomic_set(&chan_cnt, 0);
	spin_lock_init(&lock_chan);

	if( (err = proto_register(&l2tp_sk_proto, 0)) ) goto out;
	if( (err = register_pppox_proto(PX_PROTO_OL2TP, &l2tp_proto)) ) goto out_unregister_l2tp_proto;

	printk(KERN_INFO "L2TP kernel driver, v%s\n", PPPOL2TP_DRV_VERSION);

	if( (proc_cmd = create_proc_entry("l2tp_tun", 0644, proc_net)) ) {
   	 proc_cmd->read_proc = l2tp_read_cmd;
   	 proc_cmd->owner = THIS_MODULE;
    }


out:
	return err;

out_unregister_l2tp_proto:
	proto_unregister(&l2tp_sk_proto);
	goto out;
}

static void __exit l2tp_exit(void) {
	if( proc_cmd ) {
   	 remove_proc_entry("l2tp_tun", proc_net);
   	 proc_cmd = NULL;
   }

	unregister_pppox_proto(PX_PROTO_OL2TP);
	proto_unregister(&l2tp_sk_proto);
}

module_init(l2tp_init);
module_exit(l2tp_exit);

MODULE_AUTHOR( "Andrey V.Panukov <andrey.panukov@gmail.com>" );
MODULE_DESCRIPTION("PPP over L2TP over UDP");
MODULE_LICENSE("GPL");
MODULE_VERSION(PPPOL2TP_DRV_VERSION);
