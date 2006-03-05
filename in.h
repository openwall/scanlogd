/*
 * Generic packet capture interface for scanlogd.
 */

#ifndef _SCANLOGD_IN_H
#define _SCANLOGD_IN_H

#define _BSD_SOURCE
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#ifndef IP_MF
#define IP_MF				0x2000
#endif
#ifndef IP_OFFMASK
#define IP_OFFMASK			0x1fff
#endif

/*
 * Packet header as read from a packet capture interface.  In reality, the
 * TCP header can be at a different offset; this is just to get the total
 * size right.
 */
struct header {
	struct ip ip;
	struct tcphdr tcp;
	char space[60 - sizeof(struct ip)];
};

extern int in_init(void);
extern void in_run(void (*process_packet)(struct header *packet, int size));

#endif
