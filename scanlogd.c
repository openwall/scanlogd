/*
 * Copyright (c) 1998-2012 by Solar Designer
 * See LICENSE
 */

#define _BSD_SOURCE
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <time.h>
#include <syslog.h>
#include <sys/times.h>
#include <sys/types.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include "params.h"
#include "in.h"

static clock_t scan_delay_threshold, log_delay_threshold;

#define HF_DADDR_CHANGING		0x01
#define HF_SPORT_CHANGING		0x02
#define HF_TOS_CHANGING			0x04
#define HF_TTL_CHANGING			0x08

/*
 * Information we keep per each source address.
 */
struct host {
	struct host *next;		/* Next entry with the same hash */
	clock_t timestamp;		/* Last update time */
	time_t start;			/* Entry creation time */
	struct in_addr saddr, daddr;	/* Source and destination addresses */
	unsigned short sport;		/* Source port */
	int count;			/* Number of ports in the list */
	int weight;			/* Total weight of ports in the list */
	unsigned short ports[SCAN_MAX_COUNT - 1];	/* List of ports */
	unsigned char tos;		/* TOS */
	unsigned char ttl;		/* TTL */
	unsigned char flags_or;		/* TCP flags OR mask */
	unsigned char flags_and;	/* TCP flags AND mask */
	unsigned char flags;		/* HF_ flags bitmask */
};

/*
 * State information.
 */
static struct {
	struct host list[LIST_SIZE];	/* List of source addresses */
	struct host *hash[HASH_SIZE];	/* Hash: pointers into the list */
	int index;			/* Oldest entry to be replaced */
} state;

/*
 * Convert an IP address into a hash table index.
 */
static int hashfunc(struct in_addr addr)
{
	unsigned int value;
	int hash;

	value = addr.s_addr;
	hash = 0;
	do {
		hash ^= value;
	} while ((value >>= HASH_LOG));

	return hash & (HASH_SIZE - 1);
}

/*
 * Log this port scan.
 */
static void do_log(struct host *info)
{
	int limit;
	char s_saddr[32];
	char s_daddr[64 + 8 * SCAN_MAX_COUNT];
	char s_flags[16];
	char s_tos[16];
	char s_ttl[16];
	char s_time[32];
	int index, size;
	unsigned char mask;

/* We try to log everything we can at first, then remove port numbers one
 * by one if necessary until we fit into the maximum allowed length */
	limit = info->count;
prepare:

/* Source address and port number, if fixed */
	snprintf(s_saddr, sizeof(s_saddr),
		(info->flags & HF_SPORT_CHANGING) ? "%s" : "%s:%u",
		inet_ntoa(info->saddr),
		(unsigned int)ntohs(info->sport));

/* Destination address */
	snprintf(s_daddr, sizeof(s_daddr), "%s%s ports ",
		inet_ntoa(info->daddr),
		(info->flags & HF_DADDR_CHANGING) ? " and others," : "");

/* Scanned port numbers */
	for (index = 0; index < limit; index++) {
		size = strlen(s_daddr);
#ifdef LOG_MAX_LENGTH
		if (size >= LOG_MAX_LENGTH) {
			limit = index;
			break;
		}
#endif
		snprintf(s_daddr + size, sizeof(s_daddr) - size,
			"%u, ", (unsigned int)ntohs(info->ports[index]));
	}

/* TCP flags: lowercase letters for "always clear", uppercase for "always
 * set", and question marks for "sometimes set". */
	for (index = 0; index < 8; index++) {
		mask = 1 << index;
		if ((info->flags_or & mask) == (info->flags_and & mask)) {
			s_flags[index] = "fsrpauxy"[index];
			if (info->flags_or & mask)
				s_flags[index] =
				    toupper((int)(unsigned char)s_flags[index]);
		} else
			s_flags[index] = '?';
	}
	s_flags[index] = 0;

/* TOS, if fixed */
	snprintf(s_tos, sizeof(s_tos),
		(info->flags & HF_TOS_CHANGING) ? "" : ", TOS %02x",
		(unsigned int)info->tos);

/* TTL, if fixed */
	snprintf(s_ttl, sizeof(s_ttl),
		(info->flags & HF_TTL_CHANGING) ? "" : ", TTL %u",
		(unsigned int)info->ttl);

/* Scan start time */
	strftime(s_time, sizeof(s_time), "%X", localtime(&info->start));

/* Check against the length limit, and possibly re-format everything */
#ifdef LOG_MAX_LENGTH
	if (strlen(s_saddr) + strlen(s_daddr) +
	    strlen(s_tos) + strlen(s_ttl) + strlen(s_time) +
	    (4 + 5 + 8 + 2) > LOG_MAX_LENGTH) {
		if (--limit > 0) goto prepare;
	}
#endif

/* Log it all */
	syslog(SYSLOG_LEVEL,
		"%s to %s..., %s%s%s @%s",
		s_saddr, s_daddr, s_flags, s_tos, s_ttl, s_time);
}

/*
 * Log this port scan unless we're being flooded.
 */
static void safe_log(struct host *info)
{
	static clock_t last = 0;
	static int count = 0;
	clock_t now;

	now = info->timestamp;
	if (now - last > log_delay_threshold || now < last) count = 0;
	if (++count <= LOG_COUNT_THRESHOLD + 1) last = now;

	if (count <= LOG_COUNT_THRESHOLD)
		do_log(info);
	else if (count == LOG_COUNT_THRESHOLD + 1)
		syslog(SYSLOG_LEVEL, "More possible port scans follow");
}

/*
 * Process a TCP packet.
 */
static void process_packet(struct header *packet, int size)
{
	struct ip *ip;
	struct tcphdr *tcp;
	struct in_addr addr;
	unsigned short port;
	unsigned char flags;
	struct tms buf;
	clock_t now;
	struct host *current, *last, **head;
	int hash, index, count;

/* Get the IP and TCP headers */
	ip = &packet->ip;
	tcp = (struct tcphdr *)((char *)packet + ((int)ip->ip_hl << 2));

/* Sanity check */
	if (ip->ip_p != IPPROTO_TCP || (ip->ip_off & htons(IP_OFFMASK)) ||
	    (char *)tcp + sizeof(struct tcphdr) > (char *)packet + size)
		return;

/* Get the source address, destination port, and TCP flags */
	addr = ip->ip_src;
	port = tcp->th_dport;
	flags = tcp->th_flags;

/* We're using IP address 0.0.0.0 for a special purpose here, so don't let
 * them spoof us. */
	if (!addr.s_addr) return;

/* Use times(2) here not to depend on someone setting the time while we're
 * running; we need to be careful with possible return value overflows. */
	now = times(&buf);

/* Do we know this source address already? */
	count = 0;
	last = NULL;
	if ((current = *(head = &state.hash[hash = hashfunc(addr)])))
	do {
		if (current->saddr.s_addr == addr.s_addr) break;
		count++;
		if (current->next) last = current;
	} while ((current = current->next));

/* We know this address, and the entry isn't too old.  Update it. */
	if (current)
	if (now - current->timestamp <= scan_delay_threshold &&
	    now >= current->timestamp) {
/* Just update the TCP flags if we've seen this port already */
		for (index = 0; index < current->count; index++)
		if (current->ports[index] == port) {
			current->flags_or |= flags;
			current->flags_and &= flags;
			return;
		}

/* ACK and/or RST to a new port?  This could be an outgoing connection. */
		if (flags & (TH_ACK | TH_RST)) return;

/* Packet to a new port, and not ACK: update the timestamp */
		current->timestamp = now;

/* Logged this scan already?  Then leave. */
		if (current->weight >= SCAN_WEIGHT_THRESHOLD) return;

/* Update the TCP flags */
		current->flags_or |= flags;
		current->flags_and &= flags;

/* Specify if destination address, source port, TOS, or TTL are not fixed */
		if (current->daddr.s_addr != ip->ip_dst.s_addr)
			current->flags |= HF_DADDR_CHANGING;
		if (current->sport != tcp->th_sport)
			current->flags |= HF_SPORT_CHANGING;
		if (current->tos != ip->ip_tos)
			current->flags |= HF_TOS_CHANGING;
		if (current->ttl != ip->ip_ttl)
			current->flags |= HF_TTL_CHANGING;

/* Update the total weight */
		current->weight += (ntohs(port) < 1024) ?
			PORT_WEIGHT_PRIV : PORT_WEIGHT_HIGH;

/* Got enough destination ports to decide that this is a scan?  Then log it. */
		if (current->weight >= SCAN_WEIGHT_THRESHOLD) {
			safe_log(current);
			return;
		}

/* Remember the new port */
		if (current->count < SCAN_MAX_COUNT - 1)
			current->ports[current->count++] = port;

		return;
	}

/* We know this address, but the entry is outdated.  Mark it unused and
 * remove from the hash table.  We'll allocate a new entry instead since
 * this one might get re-used too soon. */
	if (current) {
		current->saddr.s_addr = 0;

		if (last)
			last->next = last->next->next;
		else if (*head)
			*head = (*head)->next;
		last = NULL;
	}

/* We don't need an ACK from a new source address */
	if (flags & TH_ACK) return;

/* Got too many source addresses with the same hash value?  Then remove the
 * oldest one from the hash table, so that they can't take too much of our
 * CPU time even with carefully chosen spoofed IP addresses. */
	if (count >= HASH_MAX && last) last->next = NULL;

/* We're going to re-use the oldest list entry, so remove it from the hash
 * table first (if it is really already in use, and isn't removed from the
 * hash table already because of the HASH_MAX check above). */

/* First, find it */
	if (state.list[state.index].saddr.s_addr)
		head = &state.hash[hashfunc(state.list[state.index].saddr)];
	else
		head = &last;
	last = NULL;
	if ((current = *head))
	do {
		if (current == &state.list[state.index]) break;
		last = current;
	} while ((current = current->next));

/* Then, remove it */
	if (current) {
		if (last)
			last->next = last->next->next;
		else if (*head)
			*head = (*head)->next;
	}

/* Get our list entry */
	current = &state.list[state.index++];
	if (state.index >= LIST_SIZE) state.index = 0;

/* Link it into the hash table */
	head = &state.hash[hash];
	current->next = *head;
	*head = current;

/* And fill in the fields */
	current->timestamp = now;
	current->start = time(NULL);
	current->saddr = addr;
	current->daddr = ip->ip_dst;
	current->sport = tcp->th_sport;
	current->count = 1;
	current->weight = (ntohs(port) < 1024) ?
		PORT_WEIGHT_PRIV : PORT_WEIGHT_HIGH;
	current->ports[0] = port;
	current->tos = ip->ip_tos;
	current->ttl = ip->ip_ttl;
	current->flags_or = current->flags_and = flags;
	current->flags = 0;
}

/*
 * Simple, but we only expect errors at startup, so this should suffice.
 */
void pexit(char *name)
{
	perror(name);
	exit(1);
}

#ifdef SCANLOGD_USER
static void drop_root(void)
{
	struct passwd *pw;
	gid_t groups[2];

	errno = 0;
	if (!(pw = getpwnam(SCANLOGD_USER))) {
		fprintf(stderr,
			"getpwnam(\"" SCANLOGD_USER "\"): %s\n",
			errno ? strerror(errno) : "No such user");
		exit(1);
	}

#ifdef SCANLOGD_CHROOT
	if (chroot(SCANLOGD_CHROOT)) return pexit("chroot");
	if (chdir("/")) return pexit("chdir");
#endif

	groups[0] = groups[1] = pw->pw_gid;
	if (setgroups(1, groups)) pexit("setgroups");
	if (setgid(pw->pw_gid)) pexit("setgid");
	if (setuid(pw->pw_uid)) pexit("setuid");
}
#elif defined(SCANLOGD_CHROOT)
#warning SCANLOGD_CHROOT makes no sense without SCANLOGD_USER; ignored.
#endif

/*
 * Hmm, what could this be?
 */
int main(void)
{
	int dev_null_fd;
	clock_t clk_tck;

/* Initialize the packet capture interface */
	if (in_init()) return 1;

/* Prepare for daemonizing */
	chdir("/");
	setsid();

/* Must do these before chroot'ing */
	tzset();
	openlog(SYSLOG_IDENT, LOG_NDELAY, SYSLOG_FACILITY);
	dev_null_fd = open("/dev/null", O_RDONLY);

/* Also do this early - who knows what this system's sysconf() relies upon */
#if defined(_SC_CLK_TCK) || !defined(CLK_TCK)
	clk_tck = sysconf(_SC_CLK_TCK);
#else
	clk_tck = CLK_TCK;
#endif
	scan_delay_threshold = SCAN_DELAY_THRESHOLD * clk_tck;
	log_delay_threshold = LOG_DELAY_THRESHOLD * clk_tck;

/* We can drop root now */
#ifdef SCANLOGD_USER
	drop_root();
#endif

/* Become a daemon */
	switch (fork()) {
	case -1:
		pexit("fork");

	case 0:
		break;

	default:
/* in_init() could have registered an atexit(3) function to restore the
 * interface, but this is not a real exit, yet (in fact, we're starting
 * up), so we use _exit(2) rather than exit(3) here */
		_exit(0);
	}

	setsid();

/* Just assume that stdin, stdout, and stderr fd's were open at startup and
 * thus are indeed not allocated to anything else. */
	if (dev_null_fd >= 0) {
		dup2(dev_null_fd, STDIN_FILENO);
		dup2(dev_null_fd, STDOUT_FILENO);
		dup2(dev_null_fd, STDERR_FILENO);
		if (dev_null_fd >= 3) close(dev_null_fd);
	}

/* Initialize the state.  All source IP addresses are set to 0.0.0.0, which
 * means the list entries aren't in use yet. */
	memset(&state, 0, sizeof(state));

/* Let's start */
	in_run(process_packet);

/* We shouldn't reach this */
	return 1;
}
