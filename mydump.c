/*Reference: http://unix.superglobalmegacorp.com/Net2/newsrc/netinet/if_ether.h.html*/

/*
author: Sharmila Duppala
Email: sduppala@cs.stonybrook.edu
Date: 13oct'17
Assignment-2 Network Security CSE 508
*/
#include <stdio.h>
#include <pcap.h>
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>



/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14


/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void
print_payload(const u_char *payload, int len);

void print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);
	
	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");
	
	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");
	
	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

return;
}

void
print_payload(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

return;
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{


	static int count = 1;                   /* packet counter */
	
    // Format time, "ddd yyyy-mm-dd hh:mm:ss zzz"
   
   
	time_t t=header->ts.tv_usec;

	time_t timer=header->ts.tv_sec;
	//printf("%ld\n", header->ts.tv_sec);
    char buffer[26];
    struct tm* tm_info;

    time(&timer);
    tm_info = localtime(&timer);

    strftime(buffer, 26, "%Y-%m-%d %H:%M:%S", tm_info);

	 struct ether_header *ethernet;  /* The ethernet header [1] */
     struct icmphdr *icmp;
	 struct ip *ip;              /* The IP header */
	 struct tcphdr *tcp;            /* The TCP header */
	 struct udphdr *udp;	//udp_header
	 //struct icmphdr *icmp; //icmp_header
	 char *payload;        /* Packet payload */
	 int i;
	int size_ip;
	int size_tcp,size_udp,size_icmp;
	int size_payload;
		
	/* define ethernet header */
	ethernet = (struct ether_header*)(packet);

	int len=strlen(args);
	char s[len];
	for(i=0;i<strlen(args);i++)
		s[i]=args[i];
	s[i]='\0';

	/* define/compute ip header offset */
	ip = (struct ip*)(packet + SIZE_ETHERNET);
	size_ip = (ip->ip_hl)*4;
	if (size_ip < 20) {

		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

	/* print source and destination IP addresses */
	//printf("%s->\n", );
	//printf("%s\n", inet_ntoa(ip->ip_dst));
	
	/* determine protocol */	
	switch(ip->ip_p) {
		case IPPROTO_TCP:
			//processing a TCP packet

			tcp = (struct tcphdr*)(packet + SIZE_ETHERNET + size_ip);
			size_tcp = (tcp->th_off)*4;
			size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
			payload = (char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
			//printf("%s and %s\n",(char *)payload,s );
			if((size_payload==0 && args!=NULL) || strstr((char *)payload,s)==NULL){
				
				return;
			}
			printf(	"%s.%ld ",buffer,header->ts.tv_usec );	
			for(i=0;i<6;i++)
			{
				if(i!=5)
					printf("%x:",ethernet->ether_shost[i]);
				else
					printf("%x->",ethernet->ether_shost[i]);
			}
			for(i=0;i<6;i++)
			{
				if(i!=5)
					printf("%x:",(ethernet->ether_dhost[i]));
				else
					printf("%x ",(ethernet->ether_dhost[i]));
			}
			printf("%s:%d->", inet_ntoa(ip->ip_src),ntohs(tcp->th_sport));
			printf("%s:%d  ", inet_ntoa(ip->ip_dst),ntohs(tcp->th_dport));
			printf(" TCP ");
			printf("type 0x%x ", ethernet->ether_type);
			printf("len %d ",header->caplen );
			if (size_tcp < 20) {
				printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
				
			}

			break;
		case IPPROTO_UDP:
			udp = (struct udphdr*)(packet + SIZE_ETHERNET + size_ip);
			size_udp=	udp->uh_ulen;
			size_payload = ntohs(ip->ip_len) - (size_ip + size_udp);
			//printf("something\n");
			payload = (char *)(packet + SIZE_ETHERNET + size_ip + size_udp);
			//printf("%s and %s\n",(char *)payload,s );
			if((size_payload==0 && args!=NULL) || strstr((char *)payload,s)==NULL)
			{
				return;
			}
			printf(	"%s.%ld ",buffer,header->ts.tv_usec );	
			for(i=0;i<6;i++)
			{
				if(i!=5)
					printf("%x:",(ethernet->ether_shost[i]));
				else
					printf("%x->",(ethernet->ether_shost[i]));
			}
			for(i=0;i<6;i++)
			{
				if(i!=5)
					printf("%x:",(ethernet->ether_dhost[i]));
				else
					printf("%x ",(ethernet->ether_dhost[i]));
			}

			printf("%s:%d->", inet_ntoa(ip->ip_src), ntohs(udp->uh_sport));
			printf("%s:%d ",inet_ntoa(ip->ip_dst), ntohs(udp->uh_dport));
			printf("UDP\n");
			printf("type 0x%d ", ethernet->ether_type);
			printf("len %d ",header->caplen );
			
			if (size_udp < 8) {
				printf("  * Invalid UDP header length: %u bytes\n", size_udp);
				
			}

			
			
			//printf("   Length of the the udp: %d\n",udp->uh_ulen);
			break;
		case IPPROTO_ICMP:

			icmp = (struct icmphdr*)(packet + SIZE_ETHERNET + size_ip);
			size_icmp = 8;
			size_payload = ntohs(ip->ip_len) - (size_ip + size_icmp);
			payload = (char *)(packet + SIZE_ETHERNET + size_ip + size_icmp);
			//printf("%s and %s\n",(char *)payload,s );
			if((size_payload==0 && args!=NULL )|| strstr((char *)payload,s)==NULL ){
				
				return;
			}

			printf(	"%s.%ld ",buffer,header->ts.tv_usec );	
			for(i=0;i<6;i++)
			{
				if(i!=5)
					printf("%x:",(ethernet->ether_shost[i]));
				else
					printf("%x->",(ethernet->ether_shost[i]));
			}
			for(i=0;i<6;i++)
			{
				if(i!=5)
					printf("%x:",(ethernet->ether_dhost[i]));
				else
					printf("%x ",(ethernet->ether_dhost[i]));
			}
			//printf(" %d->", ntohs(icmp->th_sport));
			//printf("%d\n", ntohs(icmp->th_dport));
			printf("%s->", inet_ntoa(ip->ip_src));
			printf("%s ", inet_ntoa(ip->ip_dst));
			printf("ICMP");
			break;
		case IPPROTO_IP:
			printf("IP\n");
			break;
		default:
			//printf("other\n");
			printf("Other\n");
			return;
	}
	/* compute tcp payload (segment) size */
	
	printf("\n");
	if(args!=NULL)
	{
			if (size_payload > 0 && strstr((char *)payload,s)!=NULL) {
				
				print_payload((u_char *)payload, size_payload);
		}

	}
	printf("\n");
	return;
}


int main(int argc, char **argv)
{

	char *interface = NULL;			/* capture device name */
	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
	pcap_t *handle;				/* packet capture handle */
	int i=0;
	char *filter_exp ;//= argv[2];		/* filter expression [3] */
	struct bpf_program fp;			/* compiled filter program (expression) */
	bpf_u_int32 mask;			/* subnet mask */
	bpf_u_int32 net;			/* ip */
	int num_packets = 10;			/* number of packets to capture */
	char *pcap_file=NULL;
	
	char *pattern_payload=NULL;
	for( i=1;i<argc;i++)
	{
			if(!strcmp(argv[i],"-s"))
				pattern_payload =argv[i+1];
				

				/* check for capture device name on command-line */
			if(!strcmp(argv[i],"-i"))
				interface = argv[i+1];
					
			if(!strcmp(argv[i],"-r"))
				pcap_file = argv[i+1];
	}
		
	if(i>1)
	filter_exp=argv[i-1];
	else
		filter_exp=argv[1];

	//if there is no info from the command line so we go to default device from loopupdev
	if (interface==NULL && pcap_file==NULL)
	{

		interface = pcap_lookupdev(errbuf);
		if (interface == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n",
			    errbuf);
			exit(EXIT_FAILURE);
		}

	}

	/* get network number and mask associated with capture device */
	if (pcap_lookupnet(interface, &net, &mask, errbuf) == -1) {

		fprintf(stderr, "Couldn't get netmask for device %s: %s\n",interface, errbuf);
		net = 0;
		mask = 0;
	}

	if(pcap_file==NULL)
	{
		handle = pcap_open_live(interface, SNAP_LEN, 1, 1000, errbuf);
		printf("%s\n", errbuf);
			/* make sure we're capturing on an Ethernet device [2] */
		if (pcap_datalink(handle) != DLT_EN10MB) {

		fprintf(stderr, "%s is not an Ethernet\n", interface);
		exit(EXIT_FAILURE);
		}
	}
	/* open capture device */
	else
	{

		handle = pcap_open_offline(pcap_file,errbuf);

		if (handle == NULL) {
		fprintf(stderr, "Couldn't open pcap file  %s\n",  errbuf);
		exit(EXIT_FAILURE);
		}	
	}
	/* compile the filter expression */
	if (filter_exp!= NULL )
	{

		if (pcap_compile(handle, &fp, 	filter_exp, 0, net) == -1 ) {
			fprintf(stderr, "Couldn't parse filter %s: %s\n",filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
		}
	//	if(fp==NULL)
	//		printf("oye nee fp dobbundi\n");
	/* apply the compiled filter */

		if (pcap_setfilter(handle, &fp) == -1) {
			fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
			exit(EXIT_FAILURE);
		}

	}

	
	/* now we can set our callback function */
	pcap_loop(handle, -1, got_packet, (u_char *)pattern_payload);

	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);
return 0;
}
