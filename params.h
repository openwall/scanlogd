/*
 * Configurable compile-time parameters for scanlogd.
 */

#ifndef _SCANLOGD_PARAMS_H
#define _SCANLOGD_PARAMS_H

#include <time.h>
#include <syslog.h>

/*
 * An unprivileged dummy user to run as.  The user and its UID must not be
 * used for any other purpose (that is, don't use "nobody" here).  You can
 * #undef this to let scanlogd run as root, but this is not recommended.
 */
#define SCANLOGD_USER			"scanlogd"

/*
 * An empty directory to chroot to.  The directory and its parent directories
 * must not be writable by anyone but root.
 */
#define SCANLOGD_CHROOT			"/var/empty"

/*
 * Device to monitor, if you're using libnids or libpcap directly. #undef
 * this either if you're using the raw socket interface on Linux instead,
 * or if you'd like to let libpcap autodetect this for you.
 *
 * Recent versions of libpcap support magic device name "any" and recent
 * libnids supports magic device name "all".
 */
#undef SCANLOGD_DEVICE

/*
 * Whether we want scanlogd to set the device into promiscuous mode, for
 * use with libpcap.
 */
#define SCANLOGD_PROMISC		0

/*
 * The libpcap filter expression to use when scanlogd is built with libnids
 * or direct libpcap support.  The intent is to reduce CPU load by hopefully
 * filtering out most of the uninteresting packets at the kernel level if
 * supported by libpcap on a given platform.
 */
#define SCANLOGD_PCAP_FILTER \
	"tcp and " \
	"((tcp[13] != 0x10 and tcp[13] != 0x18) or ip[6:2] & 0x3fff != 0)"

/*
 * High port numbers have a lower weight to reduce the frequency of false
 * positives, such as from passive mode FTP transfers.
 */
#define PORT_WEIGHT_PRIV		3
#define PORT_WEIGHT_HIGH		1

/*
 * Port scan detection thresholds: at least COUNT ports need to be scanned
 * from the same source, with no longer than DELAY seconds between ports.
 */
#define SCAN_MIN_COUNT			7
#define SCAN_MAX_COUNT			(SCAN_MIN_COUNT * PORT_WEIGHT_PRIV)
#define SCAN_WEIGHT_THRESHOLD		SCAN_MAX_COUNT
#define SCAN_DELAY_THRESHOLD		3

/*
 * Log flood detection thresholds: temporarily stop logging if more than
 * COUNT port scans are detected with no longer than DELAY seconds between
 * them.
 */
#define LOG_COUNT_THRESHOLD		5
#define LOG_DELAY_THRESHOLD		20

/*
 * Log line length limit, such as to fit into one SMS message. #undef this
 * for no limit.
 */
#define LOG_MAX_LENGTH			(160 - 40)

/*
 * You might want to adjust these for using your tiny append-only log file.
 */
#define SYSLOG_IDENT			"scanlogd"
#define SYSLOG_FACILITY			LOG_DAEMON
#define SYSLOG_LEVEL			LOG_ALERT

/*
 * Keep track of up to LIST_SIZE source addresses, using a hash table of
 * HASH_SIZE entries for faster lookups, but limiting hash collisions to
 * HASH_MAX source addresses per the same hash value.
 */
#define LIST_SIZE			0x100
#define HASH_LOG			9
#define HASH_SIZE			(1 << HASH_LOG)
#define HASH_MAX			0x10

#endif
