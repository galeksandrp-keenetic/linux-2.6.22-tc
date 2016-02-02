/*
 *  Point-to-Point Tunneling Protocol for Linux
 *
 *	Authors: Kozlov D. (xeb@mail.ru)
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 *
 */

#include <linux/string.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/errno.h>
#include <linux/netdevice.h>
#include <linux/net.h>
#include <linux/skbuff.h>
#include <linux/init.h>
#include <linux/ppp_channel.h>
#include <linux/ppp_defs.h>
#include <linux/if_pppox.h>
#include <linux/if_ppp.h>
#include <linux/notifier.h>
#include <linux/file.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/version.h>

#include <net/sock.h>
#include <net/protocol.h>
#include <net/ip.h>
#include <net/icmp.h>
#include <net/route.h>

#include <asm/uaccess.h>


//#define DEBUG

#define PPTP_DRIVER_VERSION "0.8.5.1"

static int log_level=0;
static int log_packets=10;

#define MAX_CALLID 65535
#define PPP_LCP_ECHREQ 0x09
#define PPP_LCP_ECHREP 0x0A

static DECLARE_BITMAP(callid_bitmap, MAX_CALLID + 1);
static struct pppox_sock **callid_sock;

#define SC_RCV_BITS	(SC_RCV_B7_1|SC_RCV_B7_0|SC_RCV_ODDP|SC_RCV_EVNP)

static DEFINE_SPINLOCK(chan_lock);
#define SK_STATE(sk) (sk)->sk_state

static int pptp_xmit(struct ppp_channel *chan, struct sk_buff *skb);
static int pptp_ppp_ioctl(struct ppp_channel *chan, unsigned int cmd,
			   unsigned long arg);
static int pptp_rcv_core(struct sock *sk,struct sk_buff *skb);

static struct ppp_channel_ops pptp_chan_ops= {
	.start_xmit = pptp_xmit,
	.ioctl=pptp_ppp_ioctl,
};

extern int (*vpn_pthrough)(struct sk_buff *skb, int in);
extern int (*vpn_pthrough_setup)(uint32_t sip, int add);

#define MISSING_WINDOW 20
#define WRAPPED( curseq, lastseq) \
    ((((curseq) & 0xffffff00) == 0) && \
     (((lastseq) & 0xffffff00 ) == 0xffffff00))

/* gre header structure: -------------------------------------------- */

#define PPTP_GRE_PROTO  0x880B
#define PPTP_GRE_VER    0x1

#define PPTP_GRE_FLAG_C	0x80
#define PPTP_GRE_FLAG_R	0x40
#define PPTP_GRE_FLAG_K	0x20
#define PPTP_GRE_FLAG_S	0x10
#define PPTP_GRE_FLAG_A	0x80

#define PPTP_GRE_IS_C(f) ((f)&PPTP_GRE_FLAG_C)
#define PPTP_GRE_IS_R(f) ((f)&PPTP_GRE_FLAG_R)
#define PPTP_GRE_IS_K(f) ((f)&PPTP_GRE_FLAG_K)
#define PPTP_GRE_IS_S(f) ((f)&PPTP_GRE_FLAG_S)
#define PPTP_GRE_IS_A(f) ((f)&PPTP_GRE_FLAG_A)

struct pptp_gre_header {
  u8 flags;		/* bitfield */
  u8 ver;			/* should be PPTP_GRE_VER (enhanced GRE) */
  u16 protocol;		/* should be PPTP_GRE_PROTO (ppp-encaps) */
  u16 payload_len;	/* size of ppp payload, not inc. gre header */
  u16 call_id;		/* peer's call_id for this session */
  u32 seq;		/* sequence number.  Present if S==1 */
  u32 ack;		/* seq number of highest packet recieved by */
  				/*  sender in this session */
} __packed;

static struct pppox_sock * lookup_chan(u16 call_id, __be32 s_addr)
{
	struct pppox_sock *sock;
	struct pptp_opt *opt;
	
	rcu_read_lock();
	sock = rcu_dereference(callid_sock[call_id]);
	if (sock) {
		opt=&sock->proto.pptp;
		if (opt->dst_addr.sin_addr.s_addr != s_addr)
			sock = NULL;
		else
			sock_hold(sk_pppox(sock));
	}
	rcu_read_unlock();
	
	return sock;
}

static int lookup_chan_dst(u16 call_id, __be32 d_addr)
{
	struct pppox_sock *sock;
	struct pptp_opt *opt;
	int i;
	
	rcu_read_lock();
	for(i = find_next_bit(callid_bitmap,MAX_CALLID,1); i < MAX_CALLID; 
	                i = find_next_bit(callid_bitmap, MAX_CALLID, i + 1)){
	    sock = rcu_dereference(callid_sock[i]);
	    if (!sock)
		continue;
	    opt = &sock->proto.pptp;
	    if (opt->dst_addr.call_id == call_id && opt->dst_addr.sin_addr.s_addr == d_addr)
			 break;
	}
	rcu_read_unlock();
	
	return i<MAX_CALLID;
}

static int add_chan(struct pppox_sock *sock)
{
	static int call_id=0;
	int res=-1;
	
	spin_lock(&chan_lock);

	if (!sock->proto.pptp.src_addr.call_id)
	{
	    call_id=find_next_zero_bit(callid_bitmap,MAX_CALLID,call_id+1);
	    if (call_id==MAX_CALLID)
				call_id=find_next_zero_bit(callid_bitmap,MAX_CALLID,1);
	    sock->proto.pptp.src_addr.call_id=call_id;
		 }
	else if (test_bit(sock->proto.pptp.src_addr.call_id,callid_bitmap))
		goto exit;

	rcu_assign_pointer(callid_sock[sock->proto.pptp.src_addr.call_id],sock);
	set_bit(sock->proto.pptp.src_addr.call_id,callid_bitmap);
	res=0;
	
exit:	
	spin_unlock(&chan_lock);

	return res;
}

static void del_chan(struct pppox_sock *sock)
{
	spin_lock(&chan_lock);
	clear_bit(sock->proto.pptp.src_addr.call_id,callid_bitmap);
	rcu_assign_pointer(callid_sock[sock->proto.pptp.src_addr.call_id],NULL);
	spin_unlock(&chan_lock);
	synchronize_rcu();
}
	
static int pptp_hard_xmit(struct sk_buff *skb) {
	int (*vhook)(struct sk_buff *skb, int in);

	if( !(vhook = rcu_dereference(vpn_pthrough)) || !vhook(skb, 0) ) {
		dst_output(skb);
    }
	return 0;
}

static int pptp_xmit(struct ppp_channel *chan, struct sk_buff *skb)
{
	struct sock *sk = (struct sock *) chan->private;
	struct pppox_sock *po = pppox_sk(sk);
	struct pptp_opt *opt=&po->proto.pptp;
	struct pptp_gre_header *hdr;
	unsigned int header_len=sizeof(*hdr);
	int err=0;
	int islcp;
	int len;
	unsigned char *data;
	u32 seq_recv;
	
	
	struct rtable *rt;     			/* Route to the other host */
	struct net_device *tdev;			/* Device to other host */
	struct iphdr  *iph;			/* Our new IP header */
	int    max_headroom;			/* The extra header space needed */

	if (SK_STATE(sk_pppox(po)) & PPPOX_DEAD)
	    goto tx_error;

	{
		struct flowi fl = { .oif = 0,
				    .nl_u = { .ip4_u =
					      { .daddr = opt->dst_addr.sin_addr.s_addr,
						.saddr = opt->src_addr.sin_addr.s_addr,
						.tos = RT_TOS(0) } },
				    .proto = IPPROTO_GRE };
		if ((err=ip_route_output_key(&rt, &fl))) {
			goto tx_error;
		}
	}

	tdev = rt->u.dst.dev;

	max_headroom = LL_RESERVED_SPACE(tdev) + sizeof(*iph)+sizeof(*hdr)+2;

	if (skb_headroom(skb) < max_headroom || skb_cloned(skb) || skb_shared(skb)) {
		struct sk_buff *new_skb = skb_realloc_headroom(skb, max_headroom);
		if (!new_skb) {
			ip_rt_put(rt);
			goto tx_error;
		}
		if (skb->sk)
		skb_set_owner_w(new_skb, skb->sk);
		kfree_skb(skb);
		skb = new_skb;
	}

	data=skb->data;
	islcp=((data[0] << 8) + data[1])== PPP_LCP && 1 <= data[2] && data[2] <= 7;

	/* compress protocol field */
	if ((opt->ppp_flags & SC_COMP_PROT) && data[0]==0 && !islcp)
		skb_pull(skb,1);

	/*
	 * Put in the address/control bytes if necessary
	 */
	if ((opt->ppp_flags & SC_COMP_AC) == 0 || islcp) {
		data=skb_push(skb,2);
		data[0]=PPP_ALLSTATIONS;
		data[1]=PPP_UI;
		if(data[4] == 1 && data[18] == 5 && data[19] == 6)
			opt->src_addr.magic_num = (data[20]<<24) + (data[21]<<16) + (data[22]<<8) + data[23];
	}
	
	len=skb->len;
  
	seq_recv = opt->seq_recv;
  
	if (opt->ack_sent == seq_recv ) header_len -= sizeof(hdr->ack);

	// Push down and install GRE header
	hdr = (struct pptp_gre_header *)skb_push(skb, header_len);
	skb_reset_transport_header(skb);

	hdr->flags       = PPTP_GRE_FLAG_K;
	hdr->ver         = PPTP_GRE_VER;
	hdr->protocol    = htons(PPTP_GRE_PROTO);
	hdr->call_id     = htons(opt->dst_addr.call_id);

	hdr->flags |= PPTP_GRE_FLAG_S;
	hdr->seq    = htonl(++opt->seq_sent);
#ifdef DEBUG
	if (log_level>=3 && opt->seq_sent<=log_packets)
		printk(KERN_INFO"PPTP[%i]: send packet: seq=%i",opt->src_addr.call_id,opt->seq_sent);
#endif
	if (opt->ack_sent != seq_recv)	{
	/* send ack with this message */
		hdr->ver |= PPTP_GRE_FLAG_A;
		hdr->ack  = htonl(seq_recv);
		opt->ack_sent = seq_recv;
#ifdef DEBUG
		if (log_level>=3 && opt->seq_sent<=log_packets)
			printk(" ack=%i",seq_recv);
#endif
	}
	hdr->payload_len = htons(len);
#ifdef DEBUG
	if (log_level>=3 && opt->seq_sent<=log_packets)
		printk("\n");
#endif

	/*
	 *	Push down and install the IP header.
	 */

	skb->transport_header = skb->network_header;
	skb_push(skb, sizeof(*iph));
	skb_reset_network_header(skb);

	memset(&(IPCB(skb)->opt), 0, sizeof(IPCB(skb)->opt));
	IPCB(skb)->flags &= ~(IPSKB_XFRM_TUNNEL_SIZE | IPSKB_XFRM_TRANSFORMED |
			      IPSKB_REROUTED);

	iph 			=	ip_hdr(skb);
	iph->version		=	4;
	iph->ihl		=	sizeof(struct iphdr) >> 2;
	if (ip_dont_fragment(sk, &rt->u.dst))
		iph->frag_off	=	htons(IP_DF);
	else
		iph->frag_off	=	0;
	iph->protocol		=	IPPROTO_GRE;
	iph->tos		=	0;
	iph->daddr		=	rt->rt_dst;
	iph->saddr		=	rt->rt_src;
	iph->ttl = dst_metric(&rt->u.dst, RTAX_HOPLIMIT);
	iph->tot_len = htons(skb->len);

	dst_release(skb->dst);
	skb->dst = &rt->u.dst;

	nf_reset(skb);

	skb->ip_summed = CHECKSUM_NONE;
	ip_select_ident_more(iph, &rt->u.dst, sk, (skb_shinfo(skb)->gso_segs ?: 1) - 1);
	ip_send_check(iph);

 	NF_HOOK(PF_INET, NF_IP_LOCAL_OUT, skb, NULL, rt->u.dst.dev, pptp_hard_xmit);
	return 1;
tx_error:
	if( skb ) kfree_skb(skb);
	return 1;
}

extern void ppp_stat_add(struct ppp_channel *chan, struct sk_buff *skb);

static int pptp_rcv_core(struct sock *sk, struct sk_buff *skb)
{
	struct pppox_sock *po = pppox_sk(sk);
	struct pptp_opt *opt=&po->proto.pptp;
	int headersize,payload_len,seq;
	u8 *payload;
	struct pptp_gre_header *header;

	if (!(SK_STATE(sk) & PPPOX_CONNECTED)) {
		if (sock_queue_rcv_skb(sk, skb))
			goto drop;
		return NET_RX_SUCCESS;
	}
	
	header = (struct pptp_gre_header *)(skb->data);

	/* test if acknowledgement present */
	if (PPTP_GRE_IS_A(header->ver)){
			u32 ack = (PPTP_GRE_IS_S(header->flags))?
					header->ack:header->seq; /* ack in different place if S = 0 */

			ack = ntohl( ack);

			if (ack > opt->ack_recv) opt->ack_recv = ack;
			/* also handle sequence number wrap-around  */
			if (WRAPPED(ack,opt->ack_recv)) opt->ack_recv = ack;
	}

	/* test if payload present */
	if (!PPTP_GRE_IS_S(header->flags)){
		goto drop;
	}

	headersize  = sizeof(*header);
	payload_len = ntohs(header->payload_len);
	seq         = ntohl(header->seq);

	/* no ack present? */
	if (!PPTP_GRE_IS_A(header->ver)) headersize -= sizeof(header->ack);
	/* check for incomplete packet (length smaller than expected) */
	if (skb->len - headersize < payload_len){
#ifdef DEBUG
		if (log_level>=1)
			printk(KERN_INFO"PPTP: discarding truncated packet (expected %d, got %d bytes)\n",
						payload_len, skb->len - headersize);
#endif
		goto drop;
	}

	payload = skb->data + headersize;
	/* check for expected sequence number */
	if(opt->src_addr.magic_num && (payload[0] == PPP_ALLSTATIONS) && (payload[1] == PPP_UI) && 
	   (PPP_PROTOCOL(payload) == PPP_LCP) && (payload[4] == PPP_LCP_ECHREQ))
	{
		unsigned int magic = opt->src_addr.magic_num;
#ifdef DEBUG
		if ( log_level >= 1)
			printk(KERN_INFO"PPTP[%i] packet %d is LCP Echo Request.\n", opt->src_addr.call_id, seq);
#endif
		payload[4] = PPP_LCP_ECHREP; /* Set Reply flag */

		/* Set our magic number */
		payload[8] = magic >> 24;
		payload[9] = magic >> 16;
		payload[10] = magic >> 8;
		payload[11] = magic;

		skb_pull(skb, headersize);

		opt->ppp_flags = SC_COMP_AC;
		opt->seq_recv = seq;

		pptp_xmit(&po->chan, skb);
		return NET_RX_DROP;
	}

	/* check for expected sequence number */
	if ( seq < opt->seq_recv + 1 || WRAPPED(opt->seq_recv, seq) ) {
		if( (payload[0] == PPP_ALLSTATIONS) && (payload[1] == PPP_UI) && 
	       (PPP_PROTOCOL(payload) == PPP_LCP) && (payload[4] == PPP_LCP_ECHREP) ) {
            		#ifdef DEBUG
	                if ( log_level >= 1)
				printk(KERN_INFO"PPTP[%i] allowing old packet %d is LCP Echo Reply.\n", opt->src_addr.call_id, seq);
			#endif
			goto ppp_lcp_echo_reply;
		}
#ifdef DEBUG
		if ( log_level >= 1)
			printk(KERN_INFO"PPTP[%i]: discarding duplicate or old packet %d (expecting %d)\n",opt->src_addr.call_id,
							seq, opt->seq_recv + 1);
#endif
	} else {
#ifdef DEBUG
		if ( log_level >= 3 && opt->seq_sent<=log_packets)
			printk(KERN_INFO"PPTP[%i]: accepting packet %d size=%i (%02x %02x %02x %02x %02x %02x)\n",opt->src_addr.call_id, seq,payload_len,
				*(payload +0),
				*(payload +1),
				*(payload +2),
				*(payload +3),
				*(payload +4),
				*(payload +5));
#endif

		opt->seq_recv = seq;
ppp_lcp_echo_reply:
		skb_pull(skb,headersize);

		if (payload[0] == PPP_ALLSTATIONS && payload[1] == PPP_UI){
			/* chop off address/control */
			if (skb->len < 3)
				goto drop;
			skb_pull(skb,2);
		}

		if( (*skb->data) & 1 ) {
			/* protocol is compressed */
			skb_push(skb, 1)[0] = 0;
		}

		skb->ip_summed = CHECKSUM_NONE;
		
		if( skb->len >= 2 && 
			 skb->data[0] == 0x00 &&
			 skb->data[1] == 0x21 ) {
			
			skb_pull(skb, 2);
			
			skb_reset_mac_header(skb);
			skb_reset_transport_header(skb);
			skb_reset_network_header(skb);
			
			ppp_stat_add(&po->chan, skb);
			
			netif_rx(skb);
		} else {
			skb_set_network_header(skb, skb->head - skb->data);
		ppp_input(&po->chan,skb);
		}

		return NET_RX_SUCCESS;
	}
drop:
	kfree_skb(skb);
       return NET_RX_DROP;
}

static int pptp_rcv(struct sk_buff *skb)
{
	struct pppox_sock *po;
	struct pptp_gre_header *header;
	struct iphdr *iph;

	if (skb->pkt_type != PACKET_HOST)
		goto drop;

	if (!pskb_may_pull(skb, 12))
		goto drop;

	iph = ip_hdr(skb);

	header = (struct pptp_gre_header *)skb->data;

	if (    /* version should be 1 */
					((header->ver & 0x7F) != PPTP_GRE_VER) ||
					/* PPTP-GRE protocol for PPTP */
					(ntohs(header->protocol) != PPTP_GRE_PROTO)||
					/* flag C should be clear   */
					PPTP_GRE_IS_C(header->flags) ||
					/* flag R should be clear   */
					PPTP_GRE_IS_R(header->flags) ||
					/* flag K should be set     */
					(!PPTP_GRE_IS_K(header->flags)) ||
					/* routing and recursion ctrl = 0  */
					((header->flags&0xF) != 0)){
			/* if invalid, discard this packet */
		if (log_level>=1)
			printk(KERN_INFO"PPTP: Discarding GRE: %X %X %X %X %X %X\n",
							header->ver&0x7F, ntohs(header->protocol),
							PPTP_GRE_IS_C(header->flags),
							PPTP_GRE_IS_R(header->flags),
							PPTP_GRE_IS_K(header->flags),
							header->flags & 0xF);
		goto drop;
	}


	if ((po=lookup_chan(htons(header->call_id),iph->saddr))) {
		dst_release(skb->dst);
		skb->dst = NULL;
		nf_reset(skb);
		
		return sk_receive_skb(sk_pppox(po), skb, 0);
	} else {
#ifdef DEBUG
		if (log_level>=1)
			printk(KERN_INFO"PPTP: Discarding packet from unknown call_id %i\n",htons(header->call_id));
#endif
	}

drop:
	kfree_skb(skb);
	return NET_RX_DROP;
}

static int pptp_bind(struct socket *sock,struct sockaddr *uservaddr,int sockaddr_len)
{
	struct sock *sk = sock->sk;
	struct sockaddr_pppox *sp = (struct sockaddr_pppox *) uservaddr;
	struct pppox_sock *po = pppox_sk(sk);
	struct pptp_opt *opt=&po->proto.pptp;
	int error=0;

#ifdef DEBUG	
	if (log_level>=1)
		printk(KERN_INFO"PPTP: bind: addr=%X call_id=%i\n",sp->sa_addr.pptp.sin_addr.s_addr,
						sp->sa_addr.pptp.call_id);
#endif
	lock_sock(sk);

	opt->src_addr=sp->sa_addr.pptp;
	if (add_chan(po))
		error=-EBUSY;

#ifdef DEBUG
	if (log_level>=1)
		printk(KERN_INFO"PPTP: using call_id %i\n",opt->src_addr.call_id);
#endif

	release_sock(sk);
	return error;
}

static int pptp_connect(struct socket *sock, struct sockaddr *uservaddr,
		  int sockaddr_len, int flags)
{
	struct sock *sk = sock->sk;
	struct sockaddr_pppox *sp = (struct sockaddr_pppox *) uservaddr;
	struct pppox_sock *po = pppox_sk(sk);
	struct pptp_opt *opt = &po->proto.pptp;
	struct rtable *rt;     			/* Route to the other host */
   int (*vsetup)(uint32_t sip, int add);
	int error=0;

	if (sp->sa_protocol != PX_PROTO_PPTP)
		return -EINVAL;
	
#ifdef DEBUG
	if (log_level>=1)
		printk(KERN_INFO"PPTP[%i]: connect: addr=%X call_id=%i\n",opt->src_addr.call_id,
						sp->sa_addr.pptp.sin_addr.s_addr,sp->sa_addr.pptp.call_id);
#endif
	
	if (lookup_chan_dst(sp->sa_addr.pptp.call_id,sp->sa_addr.pptp.sin_addr.s_addr))
		return -EALREADY;

	lock_sock(sk);
	/* Check for already bound sockets */
	if (SK_STATE(sk) & PPPOX_CONNECTED){
		error = -EBUSY;
		goto end;
	}

	/* Check for already disconnected sockets, on attempts to disconnect */
	if (SK_STATE(sk) & PPPOX_DEAD){
		error = -EALREADY;
		goto end;
	}

	if (!opt->src_addr.sin_addr.s_addr || !sp->sa_addr.pptp.sin_addr.s_addr){
		error = -EINVAL;
		goto end;
	}

	po->chan.private=sk;
	po->chan.ops=&pptp_chan_ops;

	{
		struct flowi fl = {
			.nl_u = { 
				.ip4_u = { 
					.daddr = sp->sa_addr.pptp.sin_addr.s_addr,
					.tos = RT_CONN_FLAGS(sk) 
				} 
			},
			.proto = IPPROTO_GRE 
		};

		security_sk_classify_flow(sk, &fl);
		if (ip_route_output_key(&rt, &fl)){
			error = -EHOSTUNREACH;
			goto end;
		}
		sk_setup_caps(sk, &rt->u.dst);
	}

	po->chan.mtu = dst_mtu(&rt->u.dst);
	ip_rt_put(rt);

	if( !po->chan.mtu ) 	po->chan.mtu = PPP_MTU;
	po->chan.mtu -= (sizeof(struct iphdr) + sizeof(struct pptp_gre_header) + 2);
	po->chan.hdrlen = LL_MAX_HEADER + sizeof(struct iphdr) + sizeof(struct pptp_gre_header) + 2;

	error = ppp_register_channel(&po->chan);
	if (error){
		printk(KERN_ERR "PPTP: failed to register PPP channel (%d)\n",error);
		goto end;
	}

	if( (vsetup = rcu_dereference(vpn_pthrough_setup)) ) 
		vsetup(sp->sa_addr.pptp.sin_addr.s_addr, 1);

	opt->dst_addr=sp->sa_addr.pptp;
	SK_STATE(sk) = PPPOX_CONNECTED;

 end:
	release_sock(sk);
	return error;
}

static int pptp_getname(struct socket *sock, struct sockaddr *uaddr,
		  int *usockaddr_len, int peer)
{
	int len = sizeof(struct sockaddr_pppox);
	struct sockaddr_pppox sp;

	sp.sa_family	= AF_PPPOX;
	sp.sa_protocol	= PX_PROTO_PPTP;
	sp.sa_addr.pptp=pppox_sk(sock->sk)->proto.pptp.src_addr;

	memcpy(uaddr, &sp, len);

	*usockaddr_len = len;

	return 0;
}

static int pptp_release(struct socket *sock)
{
	struct sock *sk = sock->sk;
	struct pppox_sock *po;
	struct pptp_opt *opt;
	int (*vsetup)(uint32_t sip, int add);
	int error = 0;

	if (!sk)
	    return 0;

	lock_sock(sk);

	if (sock_flag(sk, SOCK_DEAD))
	{
	    release_sock(sk);
	    return -EBADF;
	}
		
	po = pppox_sk(sk);
	opt=&po->proto.pptp;
	
	if( (vsetup = rcu_dereference(vpn_pthrough_setup)) ) 
		vsetup(opt->dst_addr.sin_addr.s_addr, 0);

	del_chan(po);

	pppox_unbind_sock(sk);
	SK_STATE(sk) = PPPOX_DEAD;

#ifdef DEBUG
	if (log_level>=1)
		printk(KERN_INFO"PPTP[%i]: release\n",opt->src_addr.call_id);
#endif

	sock_orphan(sk);
	sock->sk = NULL;

	release_sock(sk);
	sock_put(sk);

	return error;
}


static struct proto pptp_sk_proto = {
	.name	  = "PPTP",
	.owner	  = THIS_MODULE,
	.obj_size = sizeof(struct pppox_sock),
};

static struct proto_ops pptp_ops = {
    .family		= AF_PPPOX,
    .owner		= THIS_MODULE,
    .release		= pptp_release,
    .bind		=  pptp_bind,
    .connect		= pptp_connect,
    .socketpair		= sock_no_socketpair,
    .accept		= sock_no_accept,
    .getname		= pptp_getname,
    .poll		= sock_no_poll,
    .listen		= sock_no_listen,
    .shutdown		= sock_no_shutdown,
    .setsockopt		= sock_no_setsockopt,
    .getsockopt		= sock_no_getsockopt,
    .sendmsg		= sock_no_sendmsg,
    .recvmsg		= sock_no_recvmsg,
    .mmap		= sock_no_mmap,
    .ioctl		= pppox_ioctl,
};


static void pptp_sock_destruct(struct sock *sk)
{
    if (!(SK_STATE(sk) & PPPOX_DEAD)){
	    del_chan(pppox_sk(sk));
	    pppox_unbind_sock(sk);
    }
    skb_queue_purge(&sk->sk_receive_queue);
}

static int pptp_create(struct socket *sock)
{
	int error = -ENOMEM;
	struct sock *sk;
	struct pppox_sock *po;
	struct pptp_opt *opt;

	if( !(sk = sk_alloc(PF_PPPOX, GFP_KERNEL, &pptp_sk_proto, 1)) )
		goto out;

	sock_init_data(sock, sk);

	sock->state = SS_UNCONNECTED;
	sock->ops   = &pptp_ops;

	sk->sk_backlog_rcv = pptp_rcv_core;
	sk->sk_state	   = PPPOX_NONE;
	sk->sk_type	   = SOCK_STREAM;
	sk->sk_family	   = PF_PPPOX;
	sk->sk_protocol	   = PX_PROTO_PPTP;
	sk->sk_destruct	   = pptp_sock_destruct;

	po = pppox_sk(sk);
	opt=&po->proto.pptp;

	opt->seq_sent = 0; opt->seq_recv = 0xffffffff;
	opt->ack_recv = 0; opt->ack_sent = 0xffffffff;

	error = 0;
out:
	return error;
}


static int pptp_ppp_ioctl(struct ppp_channel *chan, unsigned int cmd,
			   unsigned long arg)
{
	struct sock *sk = (struct sock *) chan->private;
	struct pppox_sock *po = pppox_sk(sk);
	struct pptp_opt *opt=&po->proto.pptp;
	void __user *argp = (void __user *)arg;
	int __user *p = argp;
	int err, val;

	err = -EFAULT;
	switch (cmd) {
	case PPPIOCGFLAGS:
		val = opt->ppp_flags;
		if (put_user(val, p))
			break;
		err = 0;
		break;
	case PPPIOCSFLAGS:
		if (get_user(val, p))
			break;
		opt->ppp_flags = val & ~SC_RCV_BITS;
		err = 0;
		break;
	default:
		err = -ENOTTY;
	}

	return err;
}


static struct pppox_proto pppox_pptp_proto = {
    .create	= pptp_create,
    .owner	= THIS_MODULE,
};

static struct net_protocol net_pptp_protocol = {
	.handler	= pptp_rcv,
};

static int __init pptp_init_module(void)
{
	int err=0;

	printk(KERN_INFO "PPTP driver version " PPTP_DRIVER_VERSION "\n");

	callid_sock = __vmalloc((MAX_CALLID + 1) * sizeof(void *),
	                        GFP_KERNEL | __GFP_ZERO, PAGE_KERNEL);
	if (!callid_sock) {
		printk(KERN_ERR "PPTP: can't allocate memory\n");
		return -ENOMEM;
	}

	if (inet_add_protocol(&net_pptp_protocol, IPPROTO_GRE) < 0) {
		printk(KERN_INFO "PPTP: can't add protocol\n");
		goto out_free_mem;
	}

	err = proto_register(&pptp_sk_proto, 0);
	if (err){
		printk(KERN_INFO "PPTP: can't register sk_proto\n");
		goto out_inet_del_protocol;
	}

 	err = register_pppox_proto(PX_PROTO_PPTP, &pppox_pptp_proto);
	if (err){
		printk(KERN_INFO "PPTP: can't register pppox_proto\n");
		goto out_unregister_sk_proto;
	}
	
	return 0;
out_unregister_sk_proto:
	proto_unregister(&pptp_sk_proto);

out_inet_del_protocol:
	inet_del_protocol(&net_pptp_protocol, IPPROTO_GRE);

out_free_mem:
	vfree(callid_sock);
	return err;
}

static void __exit pptp_exit_module(void)
{
	unregister_pppox_proto(PX_PROTO_PPTP);
	proto_unregister(&pptp_sk_proto);
	inet_del_protocol(&net_pptp_protocol, IPPROTO_GRE);
	vfree(callid_sock);
}

module_init(pptp_init_module);
module_exit(pptp_exit_module);

MODULE_DESCRIPTION("Point-to-Point Tunneling Protocol for Linux");
MODULE_AUTHOR("Kozlov D. (xeb@mail.ru)");
MODULE_LICENSE("GPL");

module_param(log_level,int,0);
module_param(log_packets,int,0);
MODULE_PARM_DESC(log_level,"Logging level (default=0)");
