#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <broccoli.h>

void bro_addr_cb(BroConn* bc, void* user_data, BroAddr* a)
	{
	char addr[INET6_ADDRSTRLEN];
	if ( bro_util_is_v4_addr(a) )
		inet_ntop(AF_INET, a->addr + 3, addr, INET6_ADDRSTRLEN);
	else
		inet_ntop(AF_INET6, a->addr, addr, INET6_ADDRSTRLEN);
	printf("Received bro_addr(%s)\n", addr);

	BroEvent* event;
	event = bro_event_new("broccoli_addr");
	bro_event_add_val(event, BRO_TYPE_IPADDR, 0, a);
	bro_event_send(bc, event);
	bro_event_free(event);
	}

void bro_subnet_cb(BroConn* bc, void* user_data, BroSubnet* s)
	{
	char addr[INET6_ADDRSTRLEN];
	if ( bro_util_is_v4_addr(&s->sn_net) )
		inet_ntop(AF_INET, s->sn_net.addr + 3, addr, INET6_ADDRSTRLEN);
	else
		inet_ntop(AF_INET6, s->sn_net.addr, addr, INET6_ADDRSTRLEN);
	printf("Received bro_subnet(%s/%"PRIu32")\n", addr, s->sn_width);

	BroEvent* event;
	event = bro_event_new("broccoli_subnet");
	bro_event_add_val(event, BRO_TYPE_SUBNET, 0, s);
	bro_event_send(bc, event);
	bro_event_free(event);
	}

static void usage()
	{
	printf("broccoli-v6addrs - send/recv events w/ IPv6 address args to Bro.\n"
			"USAGE: broccoli-v6addrs [-h|-?] [-4|-6] [-p port] host\n");
	exit(0);
	}

int main(int argc, char** argv)
	{
	int opt, port, ipv4_host = 0, ipv6_host = 0;
	extern char* optarg;
	extern int optind;
	BroConn* bc;
	const char* host_str = "localhost";
	const char* port_str = "47757";
	char hostname[512];
	struct in_addr in4;
	struct in6_addr in6;

	while ( (opt = getopt(argc, argv, "?h46p:")) != -1 )
		{
		switch ( opt ) {
		case '4':
			ipv4_host = 1;
			break;
		case '6':
			ipv6_host = 1;
			break;
		case 'p':
			port_str = optarg;
			break;
		case 'h':
		case '?':
		default:
			usage();
		}
		}

	argc -= optind;
	argv += optind;

	if ( argc > 0 )
		host_str = argv[0];

	snprintf(hostname, 512, "%s:%s", host_str, port_str);

	port = strtol(port_str, 0, 0);
	if ( errno == ERANGE )
		{
		fprintf(stderr, "invalid port string: %s\n", port_str);
		return 1;
		}

	bro_init(0);

	if ( ipv4_host )
		{
		if ( inet_pton(AF_INET, host_str, &in4) <= 0 )
			{
			fprintf(stderr, "invalid IPv4 address: %s\n", host_str);
			return 1;
			}
		if ( ! (bc = bro_conn_new(&in4, htons(port), BRO_CFLAG_NONE)) )
			{
			fprintf(stderr, "bro_conn_new IPv4 failed for %s\n", hostname);
			return 1;
			}
		}
	else if ( ipv6_host )
		{
		if ( inet_pton(AF_INET6, host_str, &in6) <= 0 )
			{
			fprintf(stderr, "invalid IPv6 address: %s\n", host_str);
			return 1;
			}
		if ( ! (bc = bro_conn_new6(&in6, htons(port), BRO_CFLAG_NONE)) )
			{
			fprintf(stderr, "bro_conn_new IPv6 failed for %s\n", hostname);
			return 1;
			}
		}
	else if ( ! (bc = bro_conn_new_str(hostname, BRO_CFLAG_NONE)) )
		{
		fprintf(stderr, "bro_conn_new_str failed for %s\n", hostname);
		return 1;
		}

	bro_event_registry_add(bc, "bro_addr", (BroEventFunc)bro_addr_cb, 0);
	bro_event_registry_add(bc, "bro_subnet", (BroEventFunc)bro_subnet_cb, 0);

	if ( ! bro_conn_connect(bc) )
		{
		fprintf(stderr, "failed to connect to %s\n", hostname);
		return 1;
		}

	printf("Connected to Bro instance at: %s\n", hostname);

	int fd = bro_conn_get_fd(bc);
	fd_set fds;
	FD_ZERO(&fds);
	FD_SET(fd, &fds);
	struct timeval to;
	to.tv_sec = 3;
	to.tv_usec = 0;

	while ( select(fd+1, &fds, 0, 0, &to) > 0 )
		bro_conn_process_input(bc);

	printf("Terminating\n");
	bro_conn_delete(bc);
	return 0;
	}
