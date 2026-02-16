/*
 * Copyright (c) 2026 joshua stein <jcs@jcs.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <err.h>
#include <errno.h>
#include <netdb.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#define DNS_HEADER_SIZE		12
#define DNS_MAX_NAME		255
#define DNS_MAX_LABEL		63
#define DNS_TYPE_A		1
#define DNS_TYPE_NS		2
#define DNS_TYPE_AAAA		28
#define DNS_CLASS_IN		1
#define DNS_RCODE_NOERROR	0
#define DNS_RCODE_NXDOMAIN	3

#define DNS_FLAG_QR		0x8000	/* response */
#define DNS_FLAG_AA		0x0400	/* authoritative */
#define DNS_FLAG_RD		0x0100	/* recursion desired */
#define DNS_FLAG_RA		0x0080	/* recursion available */

int debug, verbose;

__dead void usage(void);
void logmsg(const char *, ...);
int dns_parse_name(uint8_t *, size_t, size_t, char *, size_t, size_t *);
const char *dns_type_str(uint16_t);
size_t dns_build_response(uint8_t *, size_t, uint8_t *, size_t, uint16_t,
    void *, size_t);
size_t dns_build_ns_response(uint8_t *, size_t, uint8_t *);
size_t dns_build_nxdomain(uint8_t *, size_t, uint8_t *, size_t);
int avahi_resolve(const char *, int, void *);

__dead void
usage(void)
{
	extern char *__progname;

	fprintf(stderr, "usage: %s [-dv] [-b address] -p port\n", __progname);
	exit(1);
}

void
logmsg(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if (debug)
		vprintf(fmt, ap);
	else
		vsyslog(LOG_INFO, fmt, ap);
	va_end(ap);
}

int
main(int argc, char *argv[])
{
	struct addrinfo hints, *res, *res0;
	struct sockaddr_storage ss;
	struct in_addr addr4;
	struct in6_addr addr6;
	socklen_t sslen;
	ssize_t n;
	size_t namelen, qnamelen, resplen;
	char name[DNS_MAX_NAME + 1];
	const char *bindaddr = NULL;
	const char *port = NULL;
	uint8_t qbuf[512], rbuf[512];
	uint16_t qtype, qclass;
	int ch, error, s;

	while ((ch = getopt(argc, argv, "b:dp:v")) != -1) {
		switch (ch) {
		case 'b':
			bindaddr = optarg;
			break;
		case 'd':
			debug = 1;
			break;
		case 'p':
			port = optarg;
			break;
		case 'v':
			verbose++;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (port == NULL)
		usage();

	if (!debug) {
		if (daemon(0, 0) == -1)
			err(1, "daemon");
		openlog("avahi-proxy", LOG_PID | LOG_NDELAY, LOG_DAEMON);
	}

	signal(SIGPIPE, SIG_IGN);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_PASSIVE;

	error = getaddrinfo(bindaddr, port, &hints, &res0);
	if (error != 0)
		errx(1, "getaddrinfo: %s", gai_strerror(error));

	s = -1;
	for (res = res0; res != NULL; res = res->ai_next) {
		s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (s == -1)
			continue;
		if (bind(s, res->ai_addr, res->ai_addrlen) == -1) {
			close(s);
			s = -1;
			continue;
		}
		break;
	}
	freeaddrinfo(res0);

	if (s == -1)
		err(1, "socket/bind");

	for (;;) {
		sslen = sizeof(ss);
		n = recvfrom(s, qbuf, sizeof(qbuf), 0, (struct sockaddr *)&ss,
		    &sslen);
		if (n == -1) {
			if (errno == EINTR)
				continue;
			warn("recvfrom");
			continue;
		}

		if (n < DNS_HEADER_SIZE)
			continue;

		/* parse question */
		if (dns_parse_name(qbuf, n, DNS_HEADER_SIZE, name, sizeof(name),
		    &qnamelen) == -1) {
			warnx("failed parsing DNS query");
			continue;
		}

		if (DNS_HEADER_SIZE + qnamelen + 4 > (size_t)n) {
			warnx("bogus qnamelen %zu + 4 > %zu", qnamelen, n);
			continue;
		}

		qtype = (qbuf[DNS_HEADER_SIZE + qnamelen] << 8) |
		    qbuf[DNS_HEADER_SIZE + qnamelen + 1];
		qclass = (qbuf[DNS_HEADER_SIZE + qnamelen + 2] << 8) |
		    qbuf[DNS_HEADER_SIZE + qnamelen + 3];

		if (qclass != DNS_CLASS_IN) {
			if (verbose)
				logmsg("ignoring query for non-IN (%d) name "
				    "%s\n", qclass, name);
			continue;
		}

		/* respond to ". NS" probe from unwind */
		if (strcmp(name, ".") == 0 && qtype == DNS_TYPE_NS) {
			resplen = dns_build_ns_response(rbuf, sizeof(rbuf),
			    qbuf);
			if (verbose)
				logmsg("%s %s -> localhost.\n",
				    dns_type_str(qtype), name);
		} else if ((namelen = strlen(name)) >= 6 &&
		    strcasecmp(name + namelen - 6, ".local") == 0 &&
		    qtype == DNS_TYPE_A &&
		    avahi_resolve(name, AF_INET, &addr4) == 0) {
			resplen = dns_build_response(rbuf, sizeof(rbuf),
			    qbuf, n, DNS_TYPE_A, &addr4, 4);
		} else if (namelen >= 6 &&
		    strcasecmp(name + namelen - 6, ".local") == 0 &&
		    qtype == DNS_TYPE_AAAA &&
		    avahi_resolve(name, AF_INET6, &addr6) == 0) {
			resplen = dns_build_response(rbuf, sizeof(rbuf),
			    qbuf, n, DNS_TYPE_AAAA, &addr6, 16);
		} else {
			resplen = dns_build_nxdomain(rbuf, sizeof(rbuf),
			    qbuf, n);
			if (verbose)
				logmsg("%s %s NXDOMAIN\n",
				    dns_type_str(qtype), name);
		}

		if (resplen > 0)
			sendto(s, rbuf, resplen, 0, (struct sockaddr *)&ss,
			    sslen);
	}

	return 0;
}

int
dns_parse_name(uint8_t *pkt, size_t pktlen, size_t offset, char *dst,
    size_t dstlen, size_t *lenp)
{
	size_t i, label_len, total = 0, dst_off = 0;

	for (;;) {
		if (offset >= pktlen)
			return -1;

		label_len = pkt[offset++];
		total++;

		if (label_len == 0) {
			/* root label */
			if (dst_off == 0) {
				if (dstlen < 2)
					return -1;
				dst[dst_off++] = '.';
			}
			dst[dst_off] = '\0';
			*lenp = total;
			return 0;
		}

		if (label_len > DNS_MAX_LABEL)
			return -1;
		if (offset + label_len > pktlen)
			return -1;
		if (dst_off + label_len + 1 >= dstlen)
			return -1;

		if (dst_off > 0)
			dst[dst_off++] = '.';

		for (i = 0; i < label_len; i++)
			dst[dst_off++] = pkt[offset++];
		total += label_len;
	}
}

const char *
dns_type_str(uint16_t type)
{
	switch (type) {
	case DNS_TYPE_A:
		return "A";
	case DNS_TYPE_NS:
		return "NS";
	case DNS_TYPE_AAAA:
		return "AAAA";
	default:
		return "?";
	}
}

size_t
dns_build_response(uint8_t *rbuf, size_t rlen, uint8_t *qbuf, size_t qlen,
    uint16_t type, void *addr, size_t addrlen)
{
	size_t off, qsec_len;
	uint16_t flags;

	/* question section length: from byte 12 to end of qtype/qclass */
	for (qsec_len = 0; DNS_HEADER_SIZE + qsec_len < qlen; qsec_len++) {
		if (qbuf[DNS_HEADER_SIZE + qsec_len] == 0) {
			qsec_len += 5; /* null + qtype(2) + qclass(2) */
			break;
		}
	}

	if (DNS_HEADER_SIZE + qsec_len + 12 + addrlen > rlen) {
		warnx("%s: bogus size (%d + %zu + 12 + %zu) > %zu",
		    __func__, DNS_HEADER_SIZE, qsec_len, addrlen, rlen);
		return 0;
	}

	/* copy header and question */
	memcpy(rbuf, qbuf, DNS_HEADER_SIZE + qsec_len);

	/* set response flags */
	flags = DNS_FLAG_QR | DNS_FLAG_AA | DNS_FLAG_RA;
	if (qbuf[2] & (DNS_FLAG_RD >> 8))
		flags |= DNS_FLAG_RD;
	rbuf[2] = flags >> 8;
	rbuf[3] = flags & 0xff;

	/* qdcount = 1 */
	rbuf[4] = 0; rbuf[5] = 1;
	/* ancount = 1 */
	rbuf[6] = 0; rbuf[7] = 1;
	/* nscount = 0 */
	rbuf[8] = 0; rbuf[9] = 0;
	/* arcount = 0 */
	rbuf[10] = 0; rbuf[11] = 0;

	off = DNS_HEADER_SIZE + qsec_len;

	/* answer: pointer to qname */
	rbuf[off++] = 0xc0;
	rbuf[off++] = 0x0c;
	/* type */
	rbuf[off++] = type >> 8;
	rbuf[off++] = type & 0xff;
	/* class IN */
	rbuf[off++] = 0;
	rbuf[off++] = DNS_CLASS_IN;
	/* TTL = 60 */
	rbuf[off++] = 0;
	rbuf[off++] = 0;
	rbuf[off++] = 0;
	rbuf[off++] = 60;
	/* rdlength */
	rbuf[off++] = addrlen >> 8;
	rbuf[off++] = addrlen & 0xff;
	/* rdata */
	memcpy(rbuf + off, addr, addrlen);
	off += addrlen;

	return off;
}

size_t
dns_build_ns_response(uint8_t *rbuf, size_t rlen, uint8_t *qbuf)
{
	/* "localhost." in wire format */
	static uint8_t localhost[] = {
	    9, 'l','o','c','a','l','h','o','s','t', '\0'
	};
	size_t off, qsec_len;
	uint16_t flags;

	/* question: null label + qtype(2) + qclass(2) = 5 bytes for "." */
	qsec_len = 5;

	if (DNS_HEADER_SIZE + qsec_len + 12 + sizeof(localhost) > rlen) {
		warnx("%s: bogus size (%d + %zu + 12 + %zu) > %zu",
		    __func__, DNS_HEADER_SIZE, qsec_len, sizeof(localhost),
		    rlen);
		return 0;
	}

	/* copy header and question */
	memcpy(rbuf, qbuf, DNS_HEADER_SIZE + qsec_len);

	/* set response flags */
	flags = DNS_FLAG_QR | DNS_FLAG_AA | DNS_FLAG_RA;
	if (qbuf[2] & (DNS_FLAG_RD >> 8))
		flags |= DNS_FLAG_RD;
	rbuf[2] = flags >> 8;
	rbuf[3] = flags & 0xff;

	/* qdcount = 1 */
	rbuf[4] = 0; rbuf[5] = 1;
	/* ancount = 1 */
	rbuf[6] = 0; rbuf[7] = 1;
	/* nscount = 0 */
	rbuf[8] = 0; rbuf[9] = 0;
	/* arcount = 0 */
	rbuf[10] = 0; rbuf[11] = 0;

	off = DNS_HEADER_SIZE + qsec_len;

	/* answer: pointer to qname */
	rbuf[off++] = 0xc0;
	rbuf[off++] = 0x0c;
	/* type NS */
	rbuf[off++] = 0;
	rbuf[off++] = DNS_TYPE_NS;
	/* class IN */
	rbuf[off++] = 0;
	rbuf[off++] = DNS_CLASS_IN;
	/* TTL = 86400 */
	rbuf[off++] = 0;
	rbuf[off++] = 0x01;
	rbuf[off++] = 0x51;
	rbuf[off++] = 0x80;
	/* rdlength */
	rbuf[off++] = 0;
	rbuf[off++] = sizeof(localhost);
	/* rdata: localhost. */
	memcpy(rbuf + off, localhost, sizeof(localhost));
	off += sizeof(localhost);

	return off;
}

size_t
dns_build_nxdomain(uint8_t *rbuf, size_t rlen, uint8_t *qbuf, size_t qlen)
{
	size_t qsec_len;
	uint16_t flags;

	/* find question section length */
	for (qsec_len = 0; DNS_HEADER_SIZE + qsec_len < qlen; qsec_len++) {
		if (qbuf[DNS_HEADER_SIZE + qsec_len] == 0) {
			qsec_len += 5; /* null + qtype(2) + qclass(2) */
			break;
		}
	}

	if (DNS_HEADER_SIZE + qsec_len > rlen) {
		warnx("%s: bogus size (%d + %zu) > %zu",
		    __func__, DNS_HEADER_SIZE, qsec_len, rlen);
		return 0;
	}

	/* copy header and question */
	memcpy(rbuf, qbuf, DNS_HEADER_SIZE + qsec_len);

	/* set response flags with NXDOMAIN rcode */
	flags = DNS_FLAG_QR | DNS_FLAG_AA | DNS_FLAG_RA;
	if (qbuf[2] & (DNS_FLAG_RD >> 8))
		flags |= DNS_FLAG_RD;
	rbuf[2] = flags >> 8;
	rbuf[3] = (flags & 0xff) | DNS_RCODE_NXDOMAIN;

	/* qdcount = 1 */
	rbuf[4] = 0; rbuf[5] = 1;
	/* ancount = 0 */
	rbuf[6] = 0; rbuf[7] = 0;
	/* nscount = 0 */
	rbuf[8] = 0; rbuf[9] = 0;
	/* arcount = 0 */
	rbuf[10] = 0; rbuf[11] = 0;

	return DNS_HEADER_SIZE + qsec_len;
}

int
avahi_resolve(const char *name, int af, void *addr)
{
	char buf[128], *tab, abuf[INET6_ADDRSTRLEN];
	ssize_t n;
	pid_t pid;
	int pipefd[2], status;

	if (pipe(pipefd) == -1)
		return -1;

	pid = fork();
	if (pid == -1) {
		close(pipefd[0]);
		close(pipefd[1]);
		return -1;
	}

	if (pid == 0) {
		close(pipefd[0]);
		if (dup2(pipefd[1], STDOUT_FILENO) == -1)
			_exit(1);
		close(pipefd[1]);
		execlp("avahi-resolve", "avahi-resolve",
		    af == AF_INET6 ? "-6" : "-4",
		    "-n", name,
		    (char *)NULL);
		_exit(1);
	}

	close(pipefd[1]);

	n = read(pipefd[0], buf, sizeof(buf) - 1);
	close(pipefd[0]);

	if (waitpid(pid, &status, 0) == -1 || !WIFEXITED(status) ||
	    WEXITSTATUS(status) != 0)
		return -1;

	if (n <= 0)
		return -1;

	buf[n] = '\0';

	/* strip trailing newline */
	while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r'))
		buf[--n] = '\0';

	/* avahi-resolve output: "hostname.local\t192.168.1.1\n" */
	tab = strchr(buf, '\t');
	if (tab == NULL)
		return -1;

	if (inet_pton(af, tab + 1, addr) != 1)
		return -1;

	if (verbose) {
		inet_ntop(af, addr, abuf, sizeof(abuf));
		logmsg("%s %s -> %s\n", af == AF_INET6 ? "AAAA" : "A",
		    name, abuf);
	}

	return 0;
}
