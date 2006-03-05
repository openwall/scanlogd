#define _BSD_SOURCE
#include <stdio.h>
#include <sys/types.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <nids.h>

#include "params.h"
#include "in.h"

#if !SCANLOGD_PROMISC
#if !(defined(NIDS_MAJOR) && (NIDS_MAJOR > 1 || NIDS_MINOR >= 14))
#warning "SCANLOGD_PROMISC is 0, but your libnids will set PROMISC anyway"
#endif
#endif

static void (*scanlogd_process_packet)(struct header *packet, int size);

static void nids_process_packet(struct ip *packet)
{
/* Sanity check to make sure we calculate the packet size correctly.  We
 * don't expect any fragments here since libnids should have defragmented
 * stuff for us; this is for testing with nids_register_ip_frag(). */
	if (packet->ip_off & htons(IP_MF | IP_OFFMASK))
		return;

	scanlogd_process_packet((struct header *)packet,
		(unsigned int)ntohs(packet->ip_len));
}

static void dummy_syslog(int type, int errnum, struct ip *iph, void *data)
{
}

int in_init(void)
{
#ifdef SCANLOGD_DEVICE
	nids_params.device = SCANLOGD_DEVICE;
#endif

#if defined(NIDS_MAJOR) && (NIDS_MAJOR > 1 || NIDS_MINOR >= 14)
	nids_params.n_tcp_streams = 0;
#else
	nids_params.n_tcp_streams = 1;
#endif
	nids_params.n_hosts = HASH_SIZE;
	nids_params.syslog = dummy_syslog;
	nids_params.scan_num_hosts = 0;
	nids_params.pcap_filter = SCANLOGD_PCAP_FILTER;
#if defined(NIDS_MAJOR) && (NIDS_MAJOR > 1 || NIDS_MINOR >= 14)
	nids_params.promisc = SCANLOGD_PROMISC;
#endif

	if (!nids_init()) {
		fprintf(stderr, "nids_init: %s\n", nids_errbuf);
		return 1;
	}

	return 0;
}

void in_run(void (*process_packet)(struct header *packet, int size))
{
	scanlogd_process_packet = process_packet;
	nids_register_ip(nids_process_packet);

	nids_run();
}
