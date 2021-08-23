#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <libnet.h>
#include <pcap.h>
#include <time.h>

int answer = 0;		/* flag for scan timeout */


void packet_handler(u_char * user, const struct pcap_pkthdr *header, const u_char * packet)
{
	struct tcphdr *tcp = (struct tcphdr *) (packet + LIBNET_IPV4_H + LIBNET_ETH_H);

	if (tcp->th_flags == 0x14) {
		//printf("%d/tcp closed\n", ntohs (tcp->th_sport));
		answer = 0;
	} else {
		if (tcp->th_flags == 0x12) {
			printf("%d/tcp open\n", ntohs (tcp->th_sport));
			answer = 0;
		}
	}
}


void scan(char *ip, int sp, int lp)
{
	const char *device = NULL;		/* device for sniffing/sending */
	in_addr_t destipaddr;			/* ip addr to scan */
	u_int32_t myipaddr;			/* ip addr of this host */
	libnet_ptag_t tcp = 0, ipv4 = 0;	/* libnet protocol block */
	char libnet_errbuf[LIBNET_ERRBUF_SIZE];	/* libnet error messages */
	char libpcap_errbuf[PCAP_ERRBUF_SIZE];	/* pcap error messages */
	pcap_t *handle;				/* libpcap handle */
	bpf_u_int32 netp, maskp;		/* netmask and ip */
	/* if (SYN and RST) or (SYN and ACK) flags are set */
	char *filter = "(tcp[13] == 0x14) || (tcp[13] == 0x12)";
	struct bpf_program fp;			/* compiled filter */
	time_t tv;


	/* open context */
	libnet_t *ctx = libnet_init(LIBNET_RAW4, device, libnet_errbuf);
	if (ctx == NULL) {
		fprintf(stderr,
			"Error opening context: %s\n",
			libnet_errbuf);
		exit(1);
	}

	if ((destipaddr = libnet_name2addr4(ctx, ip, LIBNET_RESOLVE)) == -1) {
		fprintf(stderr, "Invalid address: %s\n", libnet_geterror(ctx));
		exit(1);
	}


	/* get ip address of the device */
	if ((myipaddr = libnet_get_ipaddr4(ctx)) == -1) {
		fprintf(stderr, "Error getting IP: %s\n", libnet_geterror(ctx));
		exit(1);
	}

	printf("IP: %s\n", libnet_addr2name4 (destipaddr, LIBNET_DONT_RESOLVE));

	/* get device we are using for libpcap */
	if ((device = libnet_getdevice(ctx)) == NULL) {
		fprintf(stderr, "Device is NULL. Packet capture may be broken\n");
	}

	/* open the device with pcap */
	handle = pcap_open_live(device,		/* device to sniff on*/
				1500,		/* max number of bytes to capture per packet */
				0,		/* 1 to set card to promisculous mode, 0 to not */
				200,		/* time to perform packet capture in milliseconds */
				libpcap_errbuf);/* error message buffer */

	if (handle == NULL) {
		fprintf(stderr, "Error opening pcap: %s\n", libpcap_errbuf);
		exit(1);
	}

	if ((pcap_setnonblock(handle, 1, libnet_errbuf)) == -1) {
		fprintf(stderr, "Error setting nonblocking: %s\n", libpcap_errbuf);
		exit(1);
	}

	/* set the capture filter */
	if (pcap_lookupnet(device, &netp, &maskp, libpcap_errbuf) == -1) {
		fprintf(stderr, "Net lookup error: %s\n", libpcap_errbuf);
		exit(1);
	}

	if (pcap_compile(handle, &fp, filter, 0, maskp) == -1) {
		fprintf(stderr, "BPF error: %s\n", pcap_geterr(handle));
		exit(1);
	}


	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Error setting BPF: %s\n", pcap_geterr(handle));
		exit(1);
	}

	/* free memory used for the filter */
	pcap_freecode(&fp);


	/* seed pseudo random number generator */
	libnet_seed_prand(ctx);


	for (int i = sp; i <= lp; i++) {
		/* build TCP header */
		tcp = libnet_build_tcp(libnet_get_prand(LIBNET_PRu16),	/* src port */
				       i,				/* dest port */
				       libnet_get_prand(LIBNET_PRu16),	/* sequence number */
				       0,				/* acknowledgement */
				       TH_SYN,				/* control flags, SYN set */
				       7,				/* window */
				       0,				/* checksum, 0 = autofill */
				       0,				/* urgent */
				       LIBNET_TCP_H,			/* header length */
				       NULL,				/* payload */
				       0,				/* payload length */
				       ctx,				/* libnet context */
				       tcp);				/* protocol tag */

		if (tcp == -1) {
			fprintf(stderr,
				"Unable to build TCP header: %s\n",
				libnet_geterror(ctx));
			exit(1);
		}

		/* build IP header */
		ipv4 = libnet_build_ipv4(LIBNET_TCP_H + LIBNET_IPV4_H,	/* length */
				         0,				/* TOS */
					 libnet_get_prand(LIBNET_PRu16),/* IP ID */
					 0,				/* frag offset */
					 127,				/* TTL */
					 IPPROTO_TCP,			/* upper layer protocol */
					 0,				/* checksum, 0 = autofill */
					 myipaddr,			/* src IP */
					 destipaddr,			/* dest IP */
					 NULL,				/* payload */
					 0,				/* payload length */
					 ctx,				/* libnet context */
					 ipv4);				/* protocol tag */

		if (ipv4 == -1) {
			fprintf(stderr,
				"Unable to build IPv4 header: %s\n",
				libnet_geterror(ctx));
			exit(1);
		}


		/* write the packet */
		if (libnet_write(ctx) == -1) {
			fprintf(stderr,
				"Unable to send packet: %s\n",
				libnet_geterror(ctx));
			exit(1);
		}

		/* set variables for flag/counter */
		answer = 1;
		tv = time(NULL);

		/* capture the reply */
		while (answer) {
			pcap_dispatch(handle, -1, packet_handler, NULL);

			if ((time(NULL) - tv) > 0.2) {
				answer = 0; /* timed out */
				//printf("%d/tcp filtered\n", ports[i]);
			}
		}
	}

	/* exit cleanly */
	libnet_destroy(ctx);
	//pcap_close(handle);
}

