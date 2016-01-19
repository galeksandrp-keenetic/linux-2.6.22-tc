/*
 * RTSP extension for IP connection tracking
 * (C) 2003 by Tom Marshall <tmarshall at real.com>
 * based on ip_conntrack_irc.c
 *
 *      This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 *
 * Module load syntax:
 *   insmod nf_conntrack_rtsp.o ports=port1,port2,...port<MAX_PORTS>
 *                              max_outstanding=n setup_timeout=secs
 *
 * If no ports are specified, the default will be port 554.
 *
 * With max_outstanding you can define the maximum number of not yet
 * answered SETUP requests per RTSP session (default 8).
 * With setup_timeout you can specify how long the system waits for
 * an expected data channel (default 300 seconds).
 *
 * 2005-02-13: Harald Welte <laforge at netfilter.org>
 * 	- port to 2.6
 * 	- update to recent post-2.6.11 api changes
 * 2006-09-14: Steven Van Acker <deepstar at singularity.be>
 *      - removed calls to NAT code from conntrack helper: NAT no longer needed to use rtsp-conntrack
 * 2007-04-18: Michael Guntsche <mike at it-loops.com>
 * 			- Port to new NF API
 */

#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/ip.h>
#include <linux/inet.h>
#include <net/tcp.h>

#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_expect.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <linux/netfilter/nf_conntrack_rtsp.h>
#include <net/netfilter/nf_conntrack_core.h>

#define NF_NEED_STRNCASECMP
#define NF_NEED_STRTOU16
#define NF_NEED_STRTOU32
#define NF_NEED_NEXTLINE
#include <linux/netfilter_helpers.h>
#define NF_NEED_MIME_NEXTLINE
#include <linux/netfilter_mime.h>

#include <linux/ctype.h>
#define MAX_SIMUL_SETUP 8 /* XXX: use max_outstanding */
#define INFOP(fmt, args...) printk(KERN_INFO "%s: %s: " fmt, __FILE__, __FUNCTION__ , ## args)
#if 1
#define DEBUGP(fmt, args...) printk(KERN_DEBUG "%s: %s: " fmt, __FILE__, __FUNCTION__ , ## args)
#else
#define DEBUGP(fmt, args...)
#endif

DEFINE_RWLOCK(nf_conntrack_rtsp_lock);

struct rtsp_session_info {

	struct list_head list;

	/* source addr and port */
	__be32 saddr;
	__be16 sport;

	/* dest addr and port */
	__be32 daddr;
	__be16 dport;

	/* port udp */
	__be16 uport;

	/* Timer function; deletes the session. */
	struct timer_list timeout;

	/* Usage count. */
	atomic_t use;

};

static struct list_head rtsp_sessions;

#define MAX_PORTS 8
static int ports[MAX_PORTS];
static int num_ports = 0;
static int max_outstanding = 8;
static unsigned int setup_timeout = 300;

MODULE_AUTHOR("Tom Marshall <tmarshall at real.com>");
MODULE_DESCRIPTION("RTSP connection tracking module");
MODULE_LICENSE("GPL");
module_param_array(ports, int, &num_ports, 0400);
MODULE_PARM_DESC(ports, "port numbers of RTSP servers");
module_param(max_outstanding, int, 0400);
MODULE_PARM_DESC(max_outstanding, "max number of outstanding SETUP requests per RTSP session");
module_param(setup_timeout, int, 0400);
MODULE_PARM_DESC(setup_timeout, "timeout on for unestablished data channels");

static char *rtsp_buffer;
static DEFINE_SPINLOCK(rtsp_buffer_lock);

unsigned int (*nf_nat_rtsp_hook)(struct sk_buff **pskb,
				 enum ip_conntrack_info ctinfo,
				 unsigned int matchoff, unsigned int matchlen,struct ip_ct_rtsp_expect* prtspexp,
				 struct nf_conntrack_expect *exp);
void (*nf_nat_rtsp_hook_expectfn)(struct nf_conn *ct, struct nf_conntrack_expect *exp);

EXPORT_SYMBOL_GPL(nf_nat_rtsp_hook);

/*
 * Max mappings we will allow for one RTSP connection (for RTP, the number
 * of allocated ports is twice this value).  Note that SMIL burns a lot of
 * ports so keep this reasonably high.  If this is too low, you will see a
 * lot of "no free client map entries" messages.
 */
#define MAX_PORT_MAPS 16

/*** default port list was here in the masq code: 554, 3030, 4040 ***/

#define SKIP_WSPACE(ptr,len,off) while(off < len && isspace(*(ptr+off))) { off++; }

static void __rtsp_session_remove(struct rtsp_session_info *rtsp_session);

/* allocate a rtsp session */
static struct rtsp_session_info *rtsp_session_allocate(void)
{
	struct rtsp_session_info *new = NULL;
	new = kmalloc(sizeof(struct rtsp_session_info), GFP_KERNEL);
	if (new) {
		atomic_set(&new->use, 1);
	}

	return new;
}

/* init a rtsp session info */
static struct rtsp_session_info *rtsp_session_init(
		struct rtsp_session_info *i,
		__be32 saddr, __be16 sport,
		__be32 daddr, __be16 dport,
		__be16 uport)
{

	if(!i)
		return NULL;

	i->saddr = saddr;
	i->sport = sport;
	i->daddr = daddr;
	i->dport = dport;
	i->uport = uport;

	return i;
}

/* deinit a rtsp session info */
static void rtsp_session_deinit(
		struct rtsp_session_info *i)
{
	if (atomic_dec_and_test(&i->use)) {
		DEBUGP("deinit rtsp session %u.%u.%u.%u:%u-%u.%u.%u.%u:%u-%u\n",
						NIPQUAD(i->saddr),
						ntohs(i->sport),
						NIPQUAD(i->daddr),
						ntohs(i->dport),
						ntohs(i->uport));
		kfree(i);
	}
}

static void rtsp_session_timed_out(unsigned long ul_session)
{

	struct rtsp_session_info *item = (void *)ul_session;

	__rtsp_session_remove(item);

}

/* add a rtsp session to the sessions list */
static void rtsp_session_add(struct rtsp_session_info *item)
{
	if(!item)
		return;

	write_lock_bh(&nf_conntrack_rtsp_lock);

	list_add_tail(&item->list, &rtsp_sessions);

	write_unlock_bh(&nf_conntrack_rtsp_lock);

	setup_timer(&item->timeout, rtsp_session_timed_out,
			(unsigned long)item);
	item->timeout.expires = jiffies + setup_timeout * HZ;
	add_timer(&item->timeout);

	return;
}

/* delete a rtsp session from the sessions list */
static void rtsp_session_del(struct rtsp_session_info *i)
{
	DEBUGP("del rtsp session %u.%u.%u.%u:%u-%u.%u.%u.%u:%u-%u\n",
			NIPQUAD(i->saddr),
			ntohs(i->sport),
			NIPQUAD(i->daddr),
			ntohs(i->dport),
			ntohs(i->uport));

	list_del(&i->list);

}

static inline int rtsp_session_timer_refresh(struct rtsp_session_info *i)
{
	if (!del_timer(&i->timeout))
		return 0;

	i->timeout.expires = jiffies + setup_timeout*HZ;
	add_timer(&i->timeout);
	return 1;
}

static int get_session_info(
		struct sk_buff *skb,
		__be32 *src_addr,
		__be32 *dst_addr,
		__be16 *src_port,
		__be16 *dst_port)
{
	struct tcphdr *tcp_h = NULL;
	struct iphdr *ip_h = NULL;

	if(!skb)
		return 0;

	ip_h = ip_hdr(skb);
	*src_addr = ip_h->saddr;
	*dst_addr = ip_h->daddr;

//	tcp_h = tcp_hdr(skb); WTF ???
	tcp_h = (struct tcphdr *)(skb_transport_header(skb) + sizeof(struct iphdr));

	*src_port = tcp_h->source;
	*dst_port = tcp_h->dest;

	return 1;
}

static struct rtsp_session_info *__rtsp_session_find(
		__be32 addr, __be16 port)
{
	struct rtsp_session_info *i = NULL;

	list_for_each_entry(i, &rtsp_sessions, list) {
		if ((i->daddr == addr)
			&& (i->sport == port))
		{
			return i;
		}
	}

	return NULL;
}

static void __rtsp_session_remove(struct rtsp_session_info *i)
{
	write_lock_bh(&nf_conntrack_rtsp_lock);

	rtsp_session_del(i);

	write_unlock_bh(&nf_conntrack_rtsp_lock);

	rtsp_session_deinit(i);

}

static void __rtsp_session_remove_all(void)
{
	struct rtsp_session_info *i, *n;

	list_for_each_entry_safe(i, n, &rtsp_sessions, list) {
		if (del_timer(&i->timeout)) {
			atomic_set(&i->use, 1);
			__rtsp_session_remove(i);
		}
	}


}

static struct rtsp_session_info *rtsp_session_find_get(
		struct sk_buff *skb)
{
	struct rtsp_session_info *item_session = NULL;
	__be32 src_addr;
	__be32 dst_addr;
	__be16 src_port;
	__be16 dst_port;

	get_session_info(skb, &src_addr, &dst_addr, &src_port, &dst_port);

	read_lock_bh(&nf_conntrack_rtsp_lock);
	item_session = __rtsp_session_find(dst_addr, src_port);

	if (item_session)
		atomic_inc(&item_session->use);

	read_unlock_bh(&nf_conntrack_rtsp_lock);

	return item_session;
}

static struct rtsp_session_info *rtsp_session_find_release(
		struct rtsp_session_info *item)
{
	if (item)
		atomic_dec(&item->use);

	return NULL;
}
/*
 * Parse an RTSP packet.
 *
 * Returns zero if parsing failed.
 *
 * Parameters:
 *  IN      ptcp        tcp data pointer
 *  IN      tcplen      tcp data len
 *  IN/OUT  ptcpoff     points to current tcp offset
 *  OUT     phdrsoff    set to offset of rtsp headers
 *  OUT     phdrslen    set to length of rtsp headers
 *  OUT     pcseqoff    set to offset of CSeq header
 *  OUT     pcseqlen    set to length of CSeq header
 */
static int
rtsp_parse_message(char* ptcp, uint tcplen, uint* ptcpoff,
                   uint* phdrsoff, uint* phdrslen,
                   uint* pcseqoff, uint* pcseqlen,
                   uint* transoff, uint* translen)
{
	uint    entitylen = 0;
	uint    lineoff;
	uint    linelen;
	
	if (!nf_nextline(ptcp, tcplen, ptcpoff, &lineoff, &linelen))
		return 0;
	
	*phdrsoff = *ptcpoff;
	while (nf_mime_nextline(ptcp, tcplen, ptcpoff, &lineoff, &linelen)) {
		if (linelen == 0) {
			if (entitylen > 0)
				*ptcpoff += min(entitylen, tcplen - *ptcpoff);
			break;
		}
		if (lineoff+linelen > tcplen) {
			INFOP("!! overrun !!\n");
			break;
		}
		
		if (nf_strncasecmp(ptcp+lineoff, "CSeq:", 5) == 0) {
			*pcseqoff = lineoff;
			*pcseqlen = linelen;
		} 

		if (nf_strncasecmp(ptcp+lineoff, "Transport:", 10) == 0) {
			*transoff = lineoff;
			*translen = linelen;
		}
		
		if (nf_strncasecmp(ptcp+lineoff, "Content-Length:", 15) == 0) {
			uint off = lineoff+15;
			SKIP_WSPACE(ptcp+lineoff, linelen, off);
			nf_strtou32(ptcp+off, &entitylen);
		}
	}
	*phdrslen = (*ptcpoff) - (*phdrsoff);
	
	return 1;
}

/*
 * Find lo/hi client ports (if any) in transport header
 * In:
 *   ptcp, tcplen = packet
 *   tranoff, tranlen = buffer to search
 *
 * Out:
 *   pport_lo, pport_hi = lo/hi ports (host endian)
 *
 * Returns nonzero if any client ports found
 *
 * Note: it is valid (and expected) for the client to request multiple
 * transports, so we need to parse the entire line.
 */
static int
rtsp_parse_transport(char* ptran, uint tranlen,
                     struct ip_ct_rtsp_expect* prtspexp)
{
	int     rc = 0;
	uint    off = 0;
	
	if (tranlen < 10 || !iseol(ptran[tranlen-1]) ||
	    nf_strncasecmp(ptran, "Transport:", 10) != 0) {
		INFOP("sanity check failed\n");
		return 0;
	}
	
	DEBUGP("tran=%.*s\n", (int)tranlen, ptran);
	off += 10;
	SKIP_WSPACE(ptran, tranlen, off);
	
	/* Transport: tran;field;field=val,tran;field;field=val,... */
	while (off < tranlen) {
		const char* pparamend;
		uint        nextparamoff;
		
		pparamend = memchr(ptran+off, ',', tranlen-off);
		pparamend = (pparamend == NULL) ? ptran+tranlen : pparamend+1;
		nextparamoff = pparamend-ptran;

		

		while (off < nextparamoff) {
			const char* pfieldend;
			uint        nextfieldoff;
			
			pfieldend = memchr(ptran+off, ';', nextparamoff-off);
			nextfieldoff = (pfieldend == NULL) ? nextparamoff : pfieldend-ptran+1;
		   
			if (strncmp(ptran+off, "client_port=", 12) == 0) {
				u_int16_t   port;
				uint        numlen;
		    
				off += 12;
				numlen = nf_strtou16(ptran+off, &port);
				off += numlen;
				if (prtspexp->loport != 0 && prtspexp->loport != port)
					DEBUGP("multiple ports found, port %hu ignored\n", port);
				else {
					DEBUGP("lo port found : %hu\n", port);
					prtspexp->loport = prtspexp->hiport = port;
					if (ptran[off] == '-') {
						off++;
						numlen = nf_strtou16(ptran+off, &port);
						off += numlen;
						prtspexp->pbtype = pb_range;
						prtspexp->hiport = port;
						
						// If we have a range, assume rtp:
						// loport must be even, hiport must be loport+1
						if ((prtspexp->loport & 0x0001) != 0 ||
						    prtspexp->hiport != prtspexp->loport+1) {
							DEBUGP("incorrect range: %hu-%hu, correcting\n",
							       prtspexp->loport, prtspexp->hiport);
							prtspexp->loport &= 0xfffe;
							prtspexp->hiport = prtspexp->loport+1;
						}
					} else if (ptran[off] == '/') {
						off++;
						numlen = nf_strtou16(ptran+off, &port);
						off += numlen;
						prtspexp->pbtype = pb_discon;
						prtspexp->hiport = port;
					}
					rc = 1;
				}
			}
			
			/*
			 * Note we don't look for the destination parameter here.
			 * If we are using NAT, the NAT module will handle it.  If not,
			 * and the client is sending packets elsewhere, the expectation
			 * will quietly time out.
			 */
			
			off = nextfieldoff;
		}
		
		off = nextparamoff;
	}
	
	return rc;
}

void expected(struct nf_conn *ct, struct nf_conntrack_expect *exp)
{
    if(nf_nat_rtsp_hook_expectfn) {
        nf_nat_rtsp_hook_expectfn(ct,exp);
    }
}

/*** conntrack functions ***/

/* outbound packet: client->server */

static inline int
help_out(struct sk_buff **pskb, unsigned char *rb_ptr, unsigned int datalen,
		struct nf_conn *ct, enum ip_conntrack_info ctinfo)
{
	struct ip_ct_rtsp_expect expinfo;
	int dir = CTINFO2DIR(ctinfo); /* = IP_CT_DIR_ORIGINAL */
	char* pdata = rb_ptr;
	uint dataoff = 0;

	int ret = NF_ACCEPT;

	struct nf_conntrack_expect *exp;
	struct rtsp_session_info *current_rtsp_session = NULL;

	__be16 be_loport;

	memset(&expinfo, 0, sizeof(expinfo));

	while (dataoff < datalen) {

		uint cmdoff = dataoff;
		uint hdrsoff = 0;
		uint hdrslen = 0;
		uint cseqoff = 0;
		uint cseqlen = 0;
		uint transoff = 0;
		uint translen = 0;
		uint off;

		__be32 saddr;
		__be32 daddr;
		__be16 sport;
		__be16 dport;

		if (!rtsp_parse_message(pdata, datalen, &dataoff,
					&hdrsoff, &hdrslen,
					&cseqoff, &cseqlen,
					&transoff, &translen))
			break;      /* not a valid message */

		/* TODO */
		/* Add handler for TEARDOWN */

		if ((strncmp(pdata+cmdoff, "PAUSE ", 6) == 0)
			|| (strncmp(pdata+cmdoff, "GET_PARAMETER ", 14) == 0))
		{
			struct rtsp_session_info *find_rsn = NULL;
			struct nf_conntrack_expect exp_update;
			find_rsn = rtsp_session_find_get(*pskb);

			DEBUGP("found a control message from client\n");

			if (find_rsn) {
				DEBUGP("find rtsp session %u.%u.%u.%u:%u-%u.%u.%u.%u:%u-%u\n",
						NIPQUAD(find_rsn->saddr),
						ntohs(find_rsn->sport),
						NIPQUAD(find_rsn->daddr),
						ntohs(find_rsn->dport),
						ntohs(find_rsn->uport));
				rtsp_session_find_release(find_rsn);

				be_loport = find_rsn->uport;

				nf_conntrack_expect_init(&exp_update, ct->tuplehash[!dir].tuple.src.l3num,
					&ct->tuplehash[!dir].tuple.src.u3, &ct->tuplehash[!dir].tuple.dst.u3,
					IPPROTO_UDP, NULL, &be_loport); 

				exp_update.flags = 0;

				DEBUGP("expect_related update %u.%u.%u.%u:%u-%u.%u.%u.%u:%u\n",
						NIPQUAD(exp_update.tuple.src.u3.ip),
						ntohs(exp_update.tuple.src.u.udp.port),
						NIPQUAD(exp_update.tuple.dst.u3.ip),
						ntohs(exp_update.tuple.dst.u.udp.port));

				if(nf_conntrack_expect_update_timer(&exp_update) == -1) {
					DEBUGP("expect rule not found\n");
				}

				rtsp_session_timer_refresh(find_rsn);
			}
			break;

		} else if (strncmp(pdata+cmdoff, "SETUP ", 6) == 0) {

			DEBUGP("found a setup message\n");

			off = 0;
			if(translen) {
				rtsp_parse_transport(pdata+transoff, translen, &expinfo);
			}

			if (expinfo.loport == 0) {
				DEBUGP("no udp transports found\n");
				continue;   /* no udp transports found */
			}

			DEBUGP("udp transport found, ports=(%d,%hu,%hu)\n",
					(int)expinfo.pbtype, expinfo.loport, expinfo.hiport);

			exp = nf_conntrack_expect_alloc(ct);
			if (!exp) {
				ret = NF_DROP;
				break;
			}

			be_loport = htons(expinfo.loport);

			nf_conntrack_expect_init(exp, ct->tuplehash[!dir].tuple.src.l3num,
				&ct->tuplehash[!dir].tuple.src.u3, &ct->tuplehash[!dir].tuple.dst.u3,
				IPPROTO_UDP, NULL, &be_loport); 

			exp->master = ct;

			exp->expectfn = expected;
			exp->flags |= NF_CT_EXPECT_PERMANENT;

			if (expinfo.pbtype == pb_range) {
				DEBUGP("Changing expectation mask to handle multiple ports\n");
				//exp->mask.dst.u.udp.port  = 0xfffe;
			}

			DEBUGP("expect_related %u.%u.%u.%u:%u-%u.%u.%u.%u:%u\n",
					NIPQUAD(exp->tuple.src.u3.ip),
					ntohs(exp->tuple.src.u.udp.port),
					NIPQUAD(exp->tuple.dst.u3.ip),
					ntohs(exp->tuple.dst.u.udp.port));

			if (nf_nat_rtsp_hook)
				/* pass the request off to the nat helper */
				ret = nf_nat_rtsp_hook(pskb, ctinfo, hdrsoff, hdrslen, &expinfo, exp);
			else if (nf_conntrack_expect_related(exp) != 0) {
				INFOP("nf_conntrack_expect_related failed\n");
				ret  = NF_DROP;
			}
			nf_conntrack_expect_put(exp);

			if (get_session_info(*pskb, &saddr, &daddr, &sport,&dport)) {

				DEBUGP("rtsp session %u.%u.%u.%u:%u-%u.%u.%u.%u:%u\n",
						NIPQUAD(saddr),
						ntohs(sport),
						NIPQUAD(daddr),
						ntohs(dport));

				current_rtsp_session = rtsp_session_allocate();
				if(current_rtsp_session) {

					rtsp_session_init(current_rtsp_session,
							saddr, sport, daddr, dport, be_loport);

					DEBUGP("rtsp session %u.%u.%u.%u:%u-%u.%u.%u.%u:%u-%u\n",
							NIPQUAD(current_rtsp_session->saddr),
							ntohs(current_rtsp_session->sport),
							NIPQUAD(current_rtsp_session->daddr),
							ntohs(current_rtsp_session->dport),
							ntohs(current_rtsp_session->uport));

					rtsp_session_add(current_rtsp_session);

				}
			}

			break;

		} else if (strncmp(pdata+cmdoff, "TEARDOWN ", 9) == 0) {
			struct rtsp_session_info *rem_rsn = NULL;

			DEBUGP("found a down message from client\n");

			rem_rsn = rtsp_session_find_get(*pskb);

			if (rem_rsn) {
				DEBUGP("remove rtsp session %u.%u.%u.%u:%u-%u.%u.%u.%u:%u-%u\n",
						NIPQUAD(rem_rsn->saddr),
						ntohs(rem_rsn->sport),
						NIPQUAD(rem_rsn->daddr),
						ntohs(rem_rsn->dport),
						ntohs(rem_rsn->uport));
				rtsp_session_find_release(rem_rsn);

				/* remove session */
				if (del_timer(&rem_rsn->timeout)) {
					__rtsp_session_remove(rem_rsn);
				}
			}
			break;
		}
	}

	return ret;
}


static inline int
help_in(struct sk_buff **pskb, unsigned char *rb_ptr, unsigned int datalen,
		struct nf_conn *ct, enum ip_conntrack_info ctinfo)
{
	return NF_ACCEPT;
}

static int help(struct sk_buff **pskb, unsigned int protoff,
		struct nf_conn *ct, enum ip_conntrack_info ctinfo) 
{
	struct tcphdr _tcph, *th;
	unsigned int dataoff, datalen;
	char *rb_ptr;
	int ret = NF_DROP;

	/* Until there's been traffic both ways, don't look in packets. */
	if (ctinfo != IP_CT_ESTABLISHED && 
		ctinfo != IP_CT_ESTABLISHED + IP_CT_IS_REPLY) {
//		DEBUGP("conntrackinfo = %u\n", ctinfo);
		return NF_ACCEPT;
	} 

	/* Not whole TCP header? */
	th = skb_header_pointer(*pskb,protoff, sizeof(_tcph), &_tcph);

	if (!th)
		return NF_ACCEPT;
   
	/* No data ? */
	dataoff = protoff + th->doff*4;
	datalen = (*pskb)->len - dataoff;
	if (dataoff >= (*pskb)->len)
		return NF_ACCEPT;

	spin_lock_bh(&rtsp_buffer_lock);
	rb_ptr = skb_header_pointer(*pskb, dataoff,
				    (*pskb)->len - dataoff, rtsp_buffer);
	if(rb_ptr == NULL)
	{
		spin_unlock_bh(&rtsp_buffer_lock);
		return NF_ACCEPT;
	}
	//BUG_ON(rb_ptr == NULL);

#if 0
	/* Checksum invalid?  Ignore. */
	/* FIXME: Source route IP option packets --RR */
	if (tcp_v4_check(tcph, tcplen, iph->saddr, iph->daddr,
			 csum_partial((char*)tcph, tcplen, 0)))
	{
		DEBUGP("bad csum: %p %u %u.%u.%u.%u %u.%u.%u.%u\n",
		       tcph, tcplen, NIPQUAD(iph->saddr), NIPQUAD(iph->daddr));
		return NF_ACCEPT;
	}
#endif

	switch (CTINFO2DIR(ctinfo)) {
	case IP_CT_DIR_ORIGINAL:
		ret = help_out(pskb, rb_ptr, datalen, ct, ctinfo);
		break;
	case IP_CT_DIR_REPLY:
//		DEBUGP("IP_CT_DIR_REPLY\n");
		/* inbound packet: server->client */
		ret = NF_ACCEPT;
		break;
	}

	spin_unlock_bh(&rtsp_buffer_lock);

	return ret;
}

static struct nf_conntrack_helper rtsp_helpers[MAX_PORTS];
static char rtsp_names[MAX_PORTS][10];

/* This function is intentionally _NOT_ defined as __exit */
static void
fini(void)
{
	int i;
	for (i = 0; i < num_ports; i++) {
		DEBUGP("unregistering port %d\n", ports[i]);
		nf_conntrack_helper_unregister(&rtsp_helpers[i]);
	}
	kfree(rtsp_buffer);

	/* remove all list */
	__rtsp_session_remove_all();
}

static int __init
init(void)
{
	int i, ret;
	struct nf_conntrack_helper *hlpr;
	char *tmpname;

	printk("nf_conntrack_rtsp v" IP_NF_RTSP_VERSION " loading\n");

	if (max_outstanding < 1) {
		printk("nf_conntrack_rtsp: max_outstanding must be a positive integer\n");
		return -EBUSY;
	}
	if (setup_timeout < 0) {
		printk("nf_conntrack_rtsp: setup_timeout must be a positive integer\n");
		return -EBUSY;
	}

	rtsp_buffer = kmalloc(65536, GFP_KERNEL);
	if (!rtsp_buffer) 
		return -ENOMEM;

	/* If no port given, default to standard rtsp port */
	if (ports[0] == 0) {
		ports[0] = RTSP_PORT;
	}

	for (i = 0; (i < MAX_PORTS) && ports[i]; i++) {
		hlpr = &rtsp_helpers[i];
		memset(hlpr, 0, sizeof(struct nf_conntrack_helper));

		hlpr->tuple.src.u.tcp.port = htons(ports[i]);
		hlpr->tuple.dst.protonum = IPPROTO_TCP;
		hlpr->mask.src.u.tcp.port = 0xFFFF;
		hlpr->mask.dst.protonum = 0xFF;
		hlpr->max_expected = max_outstanding;
		hlpr->timeout = setup_timeout;
		hlpr->me = THIS_MODULE;
		hlpr->help = help;

		tmpname = &rtsp_names[i][0];
		if (ports[i] == RTSP_PORT) {
			sprintf(tmpname, "rtsp");
		} else {
			sprintf(tmpname, "rtsp-%d", i);
		}
		hlpr->name = tmpname;

		DEBUGP("port #%d: %d\n", i, ports[i]);

		ret = nf_conntrack_helper_register(hlpr);

		if (ret) {
			printk("nf_conntrack_rtsp: ERROR registering port %d\n", ports[i]);
			fini();
			return -EBUSY;
		}
		num_ports++;
	}

	INIT_LIST_HEAD(&rtsp_sessions);

	return 0;
}

module_init(init);
module_exit(fini);

EXPORT_SYMBOL(nf_nat_rtsp_hook_expectfn);

