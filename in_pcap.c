#define _BSD_SOURCE
#define _DEFAULT_SOURCE
#include <stdio.h>

#include <pcap.h>
#include <string.h>

#include "params.h"
#include "in.h"

static pcap_t *p;

static char *device;

int in_init(void)
{
	char error[PCAP_ERRBUF_SIZE];
	struct bpf_program filter;

#ifdef SCANLOGD_DEVICE
	device = SCANLOGD_DEVICE;
#else
	device = "any";
#endif

	if (!(p = pcap_open_live(device, sizeof(struct header),
	    SCANLOGD_PROMISC, 0, error))) {
		fprintf(stderr, "pcap_open_live: %s\n", error);
		return 1;
	}

	if (pcap_compile(p, &filter, SCANLOGD_PCAP_FILTER, 1, 0)) {
		pcap_perror(p, "pcap_compile");
		return 1;
	}

	if (pcap_setfilter(p, &filter)) {
		pcap_perror(p, "pcap_setfilter");
		return 1;
	}

	return 0;
}

void in_run(void (*process_packet)(struct header *packet, int size))
{
	int hw_size, size;
	char *packet;
	struct pcap_pkthdr header;

	switch (pcap_datalink(p)) {
	case DLT_RAW:
	case DLT_SLIP:
		hw_size = 0;
		break;

	case DLT_PPP:
		hw_size = 4;
		break;

	case DLT_EN10MB:
	default:
		hw_size = 14;
	}

        if(device == NULL || strcmp(device, "any") == 0)
               hw_size += 2;

	while (1)
	if ((packet = (char *)pcap_next(p, &header))) {
		packet += hw_size;
		size = header.caplen - hw_size;
		process_packet((struct header *)packet, size);
	}
}
