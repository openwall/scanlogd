#define _BSD_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include "params.h"
#include "in.h"

#ifndef __linux__
#warning "This code will only work on Linux; use an alternate make target"
#endif
#ifdef SCANLOGD_DEVICE
#warning "SCANLOGD_DEVICE makes no sense for the Linux raw socket interface"
#endif
#if SCANLOGD_PROMISC
#warning "SCANLOGD_PROMISC makes no sense for the Linux raw socket interface"
#endif

static int raw;

int in_init(void)
{
	if ((raw = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0) {
		perror("socket");
		return 1;
	}

	return 0;
}

void in_run(void (*process_packet)(struct header *packet, int size))
{
	struct header packet;
	int size;

	while (1)
	if ((size = read(raw, &packet, sizeof(packet))) >= sizeof(packet.ip))
		process_packet(&packet, size);
}
