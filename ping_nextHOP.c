/*  
	sudo route del -net 0.0.0.0 gw 192.168.1.1 netmask 0.0.0.0 dev enp0s25
	sudo route add -net 0.0.0.0 gw 192.168.1.1 netmask 0.0.0.0 dev enp0s25

	sudo route del -net 0.0.0.0 gw 10.10.10.1 netmask 0.0.0.0 dev wlp3s0
	sudo route add -net 0.0.0.0 gw 10.10.10.1 netmask 0.0.0.0 dev wlp3s0
	
	https://stackoverflow.com/questions/35068252/how-can-i-verify-if-an-url-https-exists-in-c-language
	https://www.pdbuchan.com/rawsock/rawsock.html
	* 
	* To clear ARP list, type command - "sudo ip -s -s neigh flush all"
*/

// Send an IPv4 ICMP echo request packet via raw socket at the link layer (ethernet frame),
// and receive echo reply packet (i.e., ping). Includes some ICMP data.
// Need to have destination MAC address.

/*
 * NOTE:-
 * 
	1.	MAC addresses are link-local addresses and are only used to route packets on a LAN, that is, 
		amongst interfaces (wireless cards, ethernet cards, etc.) that are on the same local network. 
		For ethernet, this means all the ethernet cards attached to the same cable (and via switches).

	2.	IP addresses are for traversing outside a LAN to a node located within some other LAN.

	3.	What this means is, the destination MAC address in an ethernet frame is the MAC address of the 
		interface of the NEXT HOP, not the final destination.

	4.	If I send a packet to google.com, the packet I send will have the destination MAC address as 
		my home router's interface and the destination IP address of google.com.

	5.	With IPv4, we find the MAC address of another node's interface on our LAN using ARP.

	6.	With IPv6, we use the neighbor discovery process.
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>           // close()
#include <string.h>           // strcpy, memset(), and memcpy()
#include <signal.h>
#include <time.h>
 #include <ctype.h>
#include <stdbool.h>
#include <ctype.h>
#include <netdb.h>            // struct addrinfo
#include <sys/types.h>        // needed for socket(), uint8_t, uint16_t, uint32_t
#include <sys/socket.h>       // needed for socket()
#include <netinet/in.h>       // IPPROTO_ICMP, INET_ADDRSTRLEN
#include <netinet/ip.h>       // struct ip and IP_MAXPACKET (which is 65535)
#include <netinet/ip_icmp.h>  // struct icmp, ICMP_ECHO
#include <arpa/inet.h>        // inet_pton() and inet_ntop()
#include <sys/ioctl.h>        // macro ioctl is defined
#include <bits/ioctls.h>      // defines values for argument "request" of ioctl.
#include <net/if.h>           // struct ifreq
#include <linux/if_ether.h>   // ETH_P_IP = 0x0800, ETH_P_IPV6 = 0x86DD
#include <linux/if_packet.h>  // struct sockaddr_ll (see man 7 packet)
#include <net/ethernet.h>
#include <sys/time.h>         // gettimeofday()

#include <errno.h>            // errno, perror()

#include "ping_nextHOP.h"

char interface_line[1024][1024] = {{0},{0}};

UC nextHOP		[20]	=	{0};
UC IPaddr		[20]	=	{0};
UC src_ip		[20]	=	{0};
UC MAC			[20]	=	{0};
UC OLD_MAC		[20]	=	{0};
UC interface	[20]	=	{0};

char *domain1 = "com";
char *domain2 = "co.in";
char *domain3 = "org";
char *domain4 = "net";
char *domain5 = "in";
char *domain6 = "org.net";
char *domain7 = "us";
char *domain8 = "co";
char *domain9 = "edu";
char *domain10 = "gov.in";
char *domain11 = "gov";
char *domain12 = "info";
char *domain13 = "coop";
char *domain14 = "jobs";
char *domain15 = "int";
char *domain16 = "pro";
char *domain17 = "tel";
char *domain18 = "travel";

void Debug_In_Hex_Char(UC flg,UC* buf, UI len)
{
	UI i=0;
	switch(flg)
	{
		case 1:
					for(i=0;i<len;i++)
					{
						printf("%c",buf[i]);
						//if((i+1)%20==0) 
							//printf("\n");
						fflush(stdout);
					}
					break;

		case 0:
					for(i=0;i<len;i++){
						printf("%02X",buf[i]);
						//if((i+1)%20==0) printf("\n");
					}
					printf("\n"); fflush(stdout);
					fflush(stdout);
					break;
	}
}

void exit_func(int i)
{
	signal(SIGINT,exit_func);
	exit(0);
}

void Delay_In_milliseconds(int tms)
{
    struct timeval tv;
    tv.tv_sec  = tms / 1000;
    tv.tv_usec = (tms % 1000) * 1000;
    select (0, NULL, NULL, NULL, &tv);
}

static bool f_valid = 0;

// Build IPv4 ICMP pseudo-header and call checksum function.
uint16_t icmp4_checksum (struct icmp icmphdr, uint8_t *payload, int payloadlen)
{
	char buf[IP_MAXPACKET];
	char *ptr;
	int chksumlen = 0;
	int i;

	ptr = &buf[0];  // ptr points to beginning of buffer buf

	// Copy Message Type to buf (8 bits)
	memcpy (ptr, &icmphdr.icmp_type, sizeof (icmphdr.icmp_type));
	ptr += sizeof (icmphdr.icmp_type);
	chksumlen += sizeof (icmphdr.icmp_type);

	// Copy Message Code to buf (8 bits)
	memcpy (ptr, &icmphdr.icmp_code, sizeof (icmphdr.icmp_code));
	ptr += sizeof (icmphdr.icmp_code);
	chksumlen += sizeof (icmphdr.icmp_code);

	// Copy ICMP checksum to buf (16 bits)
	// Zero, since we don't know it yet
	*ptr = 0; ptr++;
	*ptr = 0; ptr++;
	chksumlen += 2;

	// Copy Identifier to buf (16 bits)
	memcpy (ptr, &icmphdr.icmp_id, sizeof (icmphdr.icmp_id));
	ptr += sizeof (icmphdr.icmp_id);
	chksumlen += sizeof (icmphdr.icmp_id);

	// Copy Sequence Number to buf (16 bits)
	memcpy (ptr, &icmphdr.icmp_seq, sizeof (icmphdr.icmp_seq));
	ptr += sizeof (icmphdr.icmp_seq);
	chksumlen += sizeof (icmphdr.icmp_seq);

	// Copy payload to buf
	memcpy (ptr, payload, payloadlen);
	ptr += payloadlen;
	chksumlen += payloadlen;

	// Pad to the next 16-bit boundary
	for (i=0; i<payloadlen%2; i++, ptr++)
	{
		*ptr = 0;
		ptr++;
		chksumlen++;
	}

	return checksum ((uint16_t *) buf, chksumlen);
}

// Computing the internet checksum (RFC 1071).
// Note that the internet checksum does not preclude collisions.
uint16_t checksum (uint16_t *addr, int len)
{
	int count = len;
	register uint32_t sum = 0;
	uint16_t answer = 0;

	// Sum up 2-byte values until none or only one byte left.
	while (count > 1)
	{
		sum += *(addr++);
		count -= 2;
	}

	// Add left-over byte, if any.
	if (count > 0)
	{
		sum += *(uint8_t *) addr;
	}

	// Fold 32-bit sum into 16 bits; we lose information by doing this,
	// increasing the chances of a collision.
	// sum = (lower 16 bits) + (upper 16 bits shifted right 16 bits)
	while (sum >> 16)
	{
		sum = (sum & 0xffff) + (sum >> 16);
	}

	// Checksum is one's compliment of sum.
	answer = ~sum;

	return (answer);
}

// Allocate memory for an array of chars.
char * allocate_strmem (int len)
{
	void *tmp;

	if(len <= 0)
	{
		fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_strmem().\n", len);
		exit (EXIT_FAILURE);
	}
	
	tmp = (char *) malloc (len * sizeof (char));
	if (tmp != NULL)
	{
		memset (tmp, 0, len * sizeof (char));
		return (tmp);
	}
	else
	{
		fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_strmem().\n");
		exit (EXIT_FAILURE);
	}
}

// Allocate memory for an array of unsigned chars.
uint8_t * allocate_ustrmem (int len)
{
	void *tmp;

	if (len <= 0)
	{
		fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_ustrmem().\n", len);
		exit (EXIT_FAILURE);
	}

	tmp = (uint8_t *) malloc (len * sizeof (uint8_t));
	if (tmp != NULL)
	{
		memset (tmp, 0, len * sizeof (uint8_t));
		return (tmp);
	}
	else
	{
		fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_ustrmem().\n");
		exit (EXIT_FAILURE);
	}
}

// Allocate memory for an array of ints.
int * allocate_intmem (int len)
{
	void *tmp;

	if (len <= 0)
	{
		fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_intmem().\n", len);
		exit (EXIT_FAILURE);
	}
	
	tmp = (int *) malloc (len * sizeof (int));
	if (tmp != NULL)
	{
		memset (tmp, 0, len * sizeof (int));
		return (tmp);
	}
	else
	{
		fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_intmem().\n");
		exit (EXIT_FAILURE);
	}
}

int validate_number(char *str)
{
	while (*str)
	{
		if(!isdigit(*str))
		{
			//if the character is not a number, returnfalse
			return 0;
		}
		
		str++; //point to next character
	}
	return 1;
}

int validate_ip(char *ip)
{
	//check whether the IP is valid or not
	int i, num, dots = 0;
	char *ptr;
	
	if (ip == NULL)
		return 0;
	
	ptr = strtok(ip, "."); //cut the string using dor delimiter
	if (ptr == NULL)
	{
		return 0;
	}
	
	while (ptr)
	{
		if (!validate_number(ptr)) //check whether the sub string is
			return 0;
		
		num = atoi(ptr); //convert substring to number
		
		if (num >= 0 && num <= 255)
		{
			ptr = strtok(NULL, "."); //cut the next part of the string
			if (ptr != NULL)
				dots++; //increase the dot count
		} 
		else
			return 0;
	}
	
	if (dots != 3) //if the number of dots are not 3, return false
		return 0;
	
	return 1;
}

int Vaildate_URL(UC *ip)
{
	int len=0;
	int i=0;
	int IpValidity=1;
	int ret=0;
	
	len = strlen(ip);
	//printf("\nLen : %d\n\n",len); fflush(stdout);
	
	for(i=0; i < len; i++)
	{
		if ((ip[i] == '!') || 
			(ip[i] == '@') || 
			(ip[i] == '#') || 
			(ip[i] == '$') || 
			(ip[i] == '%') || 
			(ip[i] == '^') || 
			(ip[i] == '&') || 
			(ip[i] == '*') || 
			(ip[i] == '(') || 
			(ip[i] == ')') || 
			(ip[i] == '\t') || 
			(ip[i] == '\b') || 
			(ip[i] == '\n')
			)
		{
			printf("\nInvaild URL, Special Character Found!. Try again\n");	fflush(stdout);
			return -1;
		}
	}
	
	if(IpValidity==1)
	{
		ret = validate_ip(ip);
		if(ret == 0)
		{
			return -1;
		}
		else
		{
			return 0;
		}
	}
	
	return 0;
}

int remove_extra_spaces(char *input)
{
	int i = 0,j,n = 0;
	
	n = strlen(input);
	
    while (i < n)
    {
        if(input[i]==' ' && (input[i+1]==' ' || input[i-1]==' '))
        {
            for(j=i;j<n;j++)
            {
				input[j]=input[j+1];
			}
			
            n--;
        }
        else
        {
            i++;
        }
    }
    
   // printf("\ninput : %s",input); fflush(stdout);
    
	n = getWords(input);

	//~ printf("nextHOP : %s %s\n",nextHOP,interface_line[0]);	fflush(stdout);
	//~ printf("nextHOP : %s %s\n",nextHOP,interface_line[1]);	fflush(stdout);
	//~ printf("nextHOP : %s %s\n",nextHOP,interface_line[2]);	fflush(stdout);
	//~ printf("nextHOP : %s %s\n",nextHOP,interface_line[3]);	fflush(stdout);
	//~ printf("nextHOP : %s %s\n",nextHOP,interface_line[4]);	fflush(stdout);
	
	if(strcmp(nextHOP , interface_line[0]) == 0)
	{
		strcpy(MAC , interface_line[2]);
		memcpy(interface , interface_line[4] , strlen(interface_line[4])-1);
		
		return 0;
	}
	
	return 1;
}

int getWords(char *base)
{
	int n=0,i,j=0;
	
	for(i=0;TRUE;i++)
	{
		if(base[i]!=' '){
			interface_line[n][j++]=base[i];
		}
		else{
			interface_line[n][j++]='\0';//insert NULL
			n++;
			j=0;
		}
		if(base[i]=='\0')
		    break;
	}
	return n;
	
}

int Fetch_MAC_And_Interface_backup()
{
	FILE * fp=NULL;
    char * line = NULL;
    size_t len = 0;
    ssize_t read;
    int found=0;
    
    UC CMD[100]={0};

    fp = fopen((char*)"arp_data" , (const char*)"r");
    if (fp == NULL)
    {
		printf("\narp_data file is not found..\n"); fflush(stdout);
		exit(EXIT_FAILURE);
	}
	
    while ((read = getline(&line, &len, fp)) != -1)
    {
        if(remove_extra_spaces(line) == 0)
        {
			found=1;
			break;
		}
    }

	fclose(fp);
	
	if(line)	free(line);
	 
	if(found==0)
	{
		return 1;
	}

    return 0;
}

UC charTohex(UC ch)
{
	if(ch>='0' && ch <= '9')
		return ch-0x30;
	else if(ch == 'A' || ch == 'a')
		return 10;
	else if(ch == 'B' || ch == 'b')
		return 11;
	else if(ch == 'C' || ch == 'c')
		return 12;
	else if(ch == 'D' || ch == 'd')
		return 13;
	else if(ch == 'E' || ch == 'e')
		return 14;
	else if(ch == 'F' || ch == 'f')
		return 15;	
}

UC str2Hex(UC * str)
{
	return charTohex(str[0])*16+charTohex(str[1]);
}

void Fetch_Interface_IP()
{
	UC CMD	 	[200]={0};
	UC buffer 	[20]={0};
	
	FILE *fp=NULL;
	
	int len=0;
	
    sprintf((char*)CMD , (const char*)"/sbin/ifconfig %s | grep 'inet addr:' | cut -d: -f2 | awk '{ print $1}'",interface);
	system((const char*)CMD);
	
	fp = popen(CMD, "r");
	
	if(fgets(buffer, sizeof(char)*20, fp) == NULL)
	{
		printf("\nUnable to get the interface IP address. Trying another command..\n"); fflush(stdout);
		
		pclose(fp);
		
		sprintf((char*)CMD , (const char*)"ifconfig %s | egrep -o 'inet [0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'  | cut -d' ' -f2",interface);
		system((const char*)CMD);
		
		fp = popen(CMD, "r");
		
		fgets(buffer, sizeof(char)*20, fp);
	}
	
	len  = strlen((const char*)buffer);

	memcpy(src_ip , buffer , len-1);
	
	pclose(fp);
}

int Fetch_MAC_And_Interface(UC *nextHOP_IP)
{
	UC CMD		[100]	=	{0};
	UC buffer	[100]	=	{0};
	
	int len=0;
	
	static int try=0;
	
	FILE *fp=NULL;
	
	sprintf((char*)CMD , (const char*)"arp -n | grep -w -i '%s' | awk '{print $3 $5}'" , nextHOP_IP);
	system((const char*)CMD);
	
	fp = popen(CMD, "r");
	
	fgets(buffer, sizeof(char)*50, fp);
	
	len = strlen(buffer);
	//printf("\nlen : %d\n",len); fflush(stdout);
	if(len==0)
	{
		printf("\nNo data is found in the arp_data file. Going to ping that IP address.\n\n"); fflush(stdout);
		pclose(fp);
		return -1;
	}
	
	//printf("\nbuffer : %s\n",buffer); fflush(stdout);
	
	try++;
	
	memcpy(MAC , buffer , 17);
	memcpy(interface , buffer+17 , len-1-17);
	
	//~ printf("\nOLD_MAC : %s",OLD_MAC); fflush(stdout);
	//~ printf("\nMAC : %s\n",MAC); fflush(stdout);
	
	if( (strlen(OLD_MAC)>0) && (strcmp(OLD_MAC , MAC) != 0) )
	{
		try=0;
		pclose(fp);
		return 2;
	}
	
	if(try>=12)
	{
		pclose(fp);
		return 2;
	}
	
	strcpy(OLD_MAC , MAC);
	
	//printf("\nMAC : %s\ninterface : %s\n\n",MAC,interface); fflush(stdout);
	
	pclose(fp);
	
    return 0;
}

int main(int argc, char **argv)
{
	int i, status, datalen, frame_length, sendsd, recvsd, bytes, *ip_flags, timeout, trycount, trylim, done;
	
	int MAC_Not_Found	=	0;
	
	
	char *target, *dst_ip, *rec_ip;
	
	struct ip send_iphdr, *recv_iphdr;
	struct icmp send_icmphdr, *recv_icmphdr;
	
	UC tempbuffer 	[20] = {0};
	UC CMD 			[100] = {0};
	
	uint8_t *data, *src_mac, *dst_mac, *send_ether_frame, *recv_ether_frame;
	
	struct addrinfo hints, *res;
	struct sockaddr_in *ipv4;
	struct sockaddr_ll device;
	struct ifreq ifr;
	struct sockaddr from;
	socklen_t fromlen;
	struct timeval wait, t1, t2;
	struct timezone tz;
	
	double dt;
	void *tmp;
	
	static int try;
	
	// Allocate memory for various arrays.
	src_mac = allocate_ustrmem (6);
	dst_mac = allocate_ustrmem (6);
	data = allocate_ustrmem (IP_MAXPACKET);
	send_ether_frame = allocate_ustrmem (IP_MAXPACKET);
	recv_ether_frame = allocate_ustrmem (IP_MAXPACKET);
	target = allocate_strmem (40);
	dst_ip = allocate_strmem (INET_ADDRSTRLEN);
	rec_ip = allocate_strmem (INET_ADDRSTRLEN);
	ip_flags = allocate_intmem (4);

	printf("\nEnter address to ping : ");
	scanf("%s",IPaddr);
	
	//~ if(Vaildate_URL(IPaddr) < 0)
	//~ {
		//~ printf("\nInvalid IP address. Try again.\n\n"); fflush(stdout);
		//~ goto here1;
	//~ }

here2:	
	printf("\nEnter Next HOP IP address : ");
	scanf("%s",nextHOP);
	
	strcpy(tempbuffer , nextHOP);
	
	if(Vaildate_URL(tempbuffer) < 0)
	{
		printf("\nInvalid IP address. Try again.\n"); fflush(stdout);
		goto here2;
	}

here3:	
	////////////////////////////////////////////////////////////////////
	if(Fetch_MAC_And_Interface(nextHOP))
	{
		MAC_Not_Found=1;
		
		memset(CMD , 0x00 , sizeof(CMD));
		
		sprintf((char*)CMD , (const char*)"ping -c 1 %s" , nextHOP);
		system((const char*)CMD);
		
		try++;
		
		if(try>=3)
		{
			printf("\nMAC Address is not found for the next HOP IP address...\n\n"); fflush(stdout);
			exit(1);
		}
		
		goto here3;
	}
	
	if(MAC_Not_Found==1)
	{
		MAC_Not_Found=0;
		
		printf("\nWrong MAC : %s\n",MAC); fflush(stdout);
		
		printf("\nFetching MAC address of the entered Next HOP IP. Please wait....\n\n"); fflush(stdout);
		
		while(Fetch_MAC_And_Interface(nextHOP) != 2)
		{
			sleep(1);
		}
	}
	
	printf("\nCorrect MAC : %s\n\n",MAC); fflush(stdout);
	
	Fetch_Interface_IP();
	////////////////////////////////////////////////////////////////////
	
	// Submit request for a socket descriptor to look up interface.
	// We'll use it to send packets as well, so we leave it open.
	if ((sendsd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0)
	{
		perror ("socket() failed to get socket descriptor for using ioctl() ");
		exit (EXIT_FAILURE);
	}

	// Use ioctl() to look up interface name and get its MAC address.
	memset (&ifr, 0, sizeof (ifr));
	
	snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface);
	
	if (ioctl (sendsd, SIOCGIFHWADDR, &ifr) < 0)
	{
		perror ("ioctl() failed to get source MAC address ");
		return (EXIT_FAILURE);
	}
	
	// Copy source MAC address.
	memcpy (src_mac, ifr.ifr_hwaddr.sa_data, 6);
	
	// Report source MAC address to stdout.
	printf ("\nMAC address for interface %s is ", interface);
	for (i=0; i<5; i++)
	{
		printf ("%02x:", src_mac[i]);
	}
	
	printf ("%02x\n", src_mac[5]);
	
	// Find interface index from interface name and store index in
	// struct sockaddr_ll device, which will be used as an argument of sendto().
	memset (&device, 0, sizeof (device));
	
	if ((device.sll_ifindex = if_nametoindex (interface)) == 0)
	{
		perror ("if_nametoindex() failed to obtain interface index ");
		exit (EXIT_FAILURE);
	}
	
	//printf ("Index for interface %s is %i\n", interface, device.sll_ifindex);
	
	// Set destination MAC address: you need to fill these out
	
	dst_mac[0] = str2Hex(MAC+0);
	dst_mac[1] = str2Hex(MAC+3);
	dst_mac[2] = str2Hex(MAC+6);
	dst_mac[3] = str2Hex(MAC+9);
	dst_mac[4] = str2Hex(MAC+12);
	dst_mac[5] = str2Hex(MAC+15);
	
	// Report source MAC address to stdout.
	printf ("\nDestination MAC address for interface %s is ", interface);
	for (i=0; i<5; i++)
	{
		printf ("%02x:", dst_mac[i]);
	}
	
	printf ("%02x\n", dst_mac[5]);
	
	// Destination URL or IPv4 address: you need to fill this out
	strcpy (target, IPaddr);

	printf("\nsrc_ip : %s",src_ip); fflush(stdout);
	printf("\ntarget : %s",target); fflush(stdout);
	printf("\nNext HOP : %s",nextHOP); fflush(stdout);
	printf("\nMAC : %s",MAC); fflush(stdout);
	printf("\ninterface : %s\n\n",interface); fflush(stdout);
	
	// Fill out hints for getaddrinfo().
	memset (&hints, 0, sizeof (struct addrinfo));
	
	hints.ai_family 	=	AF_INET;
	hints.ai_socktype 	=	SOCK_STREAM;
	hints.ai_flags 		=	hints.ai_flags | AI_CANONNAME;

	// Resolve target using getaddrinfo().
	if ((status = getaddrinfo (target, NULL, &hints, &res)) != 0)
	{
		fprintf (stderr, "getaddrinfo() failed: %s\n", gai_strerror (status));
		exit (EXIT_FAILURE);
	}
	
	ipv4 = (struct sockaddr_in *) res->ai_addr;
	
	tmp = &(ipv4->sin_addr);
	
	if(inet_ntop (AF_INET, tmp, dst_ip, INET_ADDRSTRLEN) == NULL)
	{
		status = errno;
		fprintf (stderr, "inet_ntop() failed.\nError message: %s", strerror (status));
		exit (EXIT_FAILURE);
	}
	
	printf("\ndst_ip : %s\n\n",dst_ip); fflush(stdout);
	
	freeaddrinfo (res);

	// Fill out sockaddr_ll.
	device.sll_family = AF_PACKET;
	
	memcpy (device.sll_addr, src_mac, 6);
	
	device.sll_halen = 6;
	
	// ICMP data
	datalen = 4;
	
	data[0] = 'T';
	data[1] = 'e';
	data[2] = 's';
	data[3] = 't';
	
	// IPv4 header
	
	// IPv4 header length (4 bits): Number of 32-bit words in header = 5
	send_iphdr.ip_hl = IP4_HDRLEN / sizeof (uint32_t);

	// Internet Protocol version (4 bits): IPv4
	send_iphdr.ip_v = 4;

	// Type of service (8 bits)
	send_iphdr.ip_tos = 0;

	// Total length of datagram (16 bits): IP header + ICMP header + ICMP data
	send_iphdr.ip_len = htons (IP4_HDRLEN + ICMP_HDRLEN + datalen);

	// ID sequence number (16 bits): unused, since single datagram
	send_iphdr.ip_id = htons (0);

	// Flags, and Fragmentation offset (3, 13 bits): 0 since single datagram

	// Zero (1 bit)
	ip_flags[0] = 0;

	// Do not fragment flag (1 bit)
	ip_flags[1] = 0;

	// More fragments following flag (1 bit)
	ip_flags[2] = 0;

	// Fragmentation offset (13 bits)
	ip_flags[3] = 0;

	send_iphdr.ip_off = htons ((ip_flags[0] << 15) + (ip_flags[1] << 14) + (ip_flags[2] << 13) +  ip_flags[3]);

	// Time-to-Live (8 bits): default to maximum value
	send_iphdr.ip_ttl = 255;
	
	// Transport layer protocol (8 bits): 1 for ICMP
	send_iphdr.ip_p = IPPROTO_ICMP;
	
	// Source IPv4 address (32 bits)
	if ((status = inet_pton (AF_INET, src_ip, &(send_iphdr.ip_src))) != 1)
	{
		fprintf (stderr, "inet_pton() failed.\nError message: %s", strerror (status));
		exit (EXIT_FAILURE);
	}
	
	// Destination IPv4 address (32 bits)
	if ((status = inet_pton (AF_INET, dst_ip, &(send_iphdr.ip_dst))) != 1)
	{
		fprintf (stderr, "inet_pton() failed.\nError message: %s", strerror (status));
		exit (EXIT_FAILURE);
	}

	// IPv4 header checksum (16 bits): set to 0 when calculating checksum
	send_iphdr.ip_sum = 0;
	send_iphdr.ip_sum = checksum ((uint16_t *) &send_iphdr, IP4_HDRLEN);

	// ICMP header

	// Message Type (8 bits): echo request
	send_icmphdr.icmp_type = ICMP_ECHO;

	// Message Code (8 bits): echo request
	send_icmphdr.icmp_code = 0;

	// Identifier (16 bits): usually pid of sending process - pick a number
	send_icmphdr.icmp_id = htons (1000);

	// Sequence Number (16 bits): starts at 0
	send_icmphdr.icmp_seq = htons (0);

	// ICMP header checksum (16 bits): set to 0 when calculating checksum
	send_icmphdr.icmp_cksum = icmp4_checksum (send_icmphdr, data, datalen);

	// Fill out ethernet frame header.

	// Ethernet frame length = ethernet header (MAC + MAC + ethernet type) + ethernet data (IP header + ICMP header + ICMP data)
	frame_length = 6 + 6 + 2 + IP4_HDRLEN + ICMP_HDRLEN + datalen;

	// Destination and Source MAC addresses
	memcpy (send_ether_frame, dst_mac, 6);
	memcpy (send_ether_frame + 6, src_mac, 6);
	
	// Next is ethernet type code (ETH_P_IP for IPv4).
	// http://www.iana.org/assignments/ethernet-numbers
	send_ether_frame[12] = ETH_P_IP / 256;
	send_ether_frame[13] = ETH_P_IP % 256;
	
	// Next is ethernet frame data (IPv4 header + ICMP header + ICMP data).
	
	// IPv4 header
	memcpy (send_ether_frame + ETH_HDRLEN, &send_iphdr, IP4_HDRLEN);
	
	// ICMP header
	memcpy (send_ether_frame + ETH_HDRLEN + IP4_HDRLEN, &send_icmphdr, ICMP_HDRLEN);
	
	// ICMP data
	memcpy (send_ether_frame + ETH_HDRLEN + IP4_HDRLEN + ICMP_HDRLEN, data, datalen);
	
	// Submit request for a raw socket descriptor to receive packets.
	if ((recvsd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0)
	{
		perror ("socket() failed to obtain a receive socket descriptor ");
		exit (EXIT_FAILURE);
	}

	// Set maximum number of tries to ping remote host before giving up.
	trylim =10;
	trycount = 0;
	
	// Cast recv_iphdr as pointer to IPv4 header within received ethernet frame.
	recv_iphdr = (struct ip *) (recv_ether_frame + ETH_HDRLEN);
	
	// Cast recv_icmphdr as pointer to ICMP header within received ethernet frame.
	recv_icmphdr = (struct icmp *) (recv_ether_frame + ETH_HDRLEN + IP4_HDRLEN);

	done = 0;
	
	while(1)
	{
		// Send ethernet frame to socket.
		if ((bytes = sendto (sendsd, send_ether_frame, frame_length, 0, (struct sockaddr *) &device, sizeof (device))) <= 0)
		{
			perror ("sendto() failed ");
			exit (EXIT_FAILURE);
		}
		
		// Start timer.
		(void) gettimeofday (&t1, &tz);
		
		// Set time for the socket to timeout and give up waiting for a reply.
		timeout = 2;
		wait.tv_sec  = timeout;  
		wait.tv_usec = 0;
		
		setsockopt (recvsd, SOL_SOCKET, SO_RCVTIMEO, (char *) &wait, sizeof (struct timeval));
		
		// Listen for incoming ethernet frame from socket recvsd.
		// We expect an ICMP ethernet frame of the form:
		//     MAC (6 bytes) + MAC (6 bytes) + ethernet type (2 bytes)
		//     + ethernet data (IPv4 header + ICMP header)
		// Keep at it for 'timeout' seconds, or until we get an ICMP reply.
		
		// RECEIVE LOOP
		while(1)
		{
			memset (recv_ether_frame, 0, IP_MAXPACKET * sizeof (uint8_t));
			memset (&from, 0, sizeof (from));
			fromlen = sizeof (from);
			
			if ((bytes = recvfrom (recvsd, recv_ether_frame, IP_MAXPACKET, 0, (struct sockaddr *) &from, &fromlen)) < 0)
			{
				status = errno;
				
				// Deal with error conditions first.
				if (status == EAGAIN)
				{
					// EAGAIN = 11
					printf ("No reply within %i seconds.\n", timeout);
					trycount++;
					break;  // Break out of Receive loop.
				}
				else if (status == EINTR)
				{ 
					// EINTR = 4
					continue;  // Something weird happened, but let's keep listening.
				}
				else
				{
					perror ("recvfrom() failed ");
					exit (EXIT_FAILURE);
				}
			}
			
			//~ printf("\nrecv_ether_frame : %d %d %d\n\n",recv_ether_frame[12]<<8,recv_ether_frame[13],ETH_P_IP); fflush(stdout);
			//~ printf("\nrecv_iphdr->ip_p : %d %d",recv_iphdr->ip_p,IPPROTO_ICMP); fflush(stdout);
			//~ printf("\nrecv_icmphdr->icmp_type : %d %d",recv_icmphdr->icmp_type,ICMP_ECHOREPLY); fflush(stdout);
			//~ printf("\nrecv_icmphdr->icmp_code : %d %d",recv_icmphdr->icmp_code); fflush(stdout);
			
			// Check for an IP ethernet frame, carrying ICMP echo reply. If not, ignore and keep listening.
			if ((((recv_ether_frame[12] << 8) + recv_ether_frame[13]) == ETH_P_IP) && (recv_iphdr->ip_p == IPPROTO_ICMP) && (recv_icmphdr->icmp_type == ICMP_ECHOREPLY) && (recv_icmphdr->icmp_code == 0))
			{
				// Stop timer and calculate how long it took to get a reply.
				(void) gettimeofday (&t2, &tz);
				
				dt = (double) (t2.tv_sec - t1.tv_sec) * 1000.0 + (double) (t2.tv_usec - t1.tv_usec) / 1000.0;
				
				// Extract source IP address from received ethernet frame.
				if (inet_ntop (AF_INET, &(recv_iphdr->ip_src.s_addr), rec_ip, INET_ADDRSTRLEN) == NULL)
				{
					status = errno;
					fprintf (stderr, "inet_ntop() failed.\nError message: %s", strerror (status));
					exit (EXIT_FAILURE);
				}
				
				// Report source IPv4 address and time for reply.
				printf ("%s  %g ms (%i bytes received)\n", rec_ip, dt, bytes);
				break;  // Break out of Receive loop.
			}  // End if IP ethernet frame carrying ICMP_ECHOREPLY
		}  // End of Receive loop.
		
		// We ran out of tries, so let's give up.
		if (trycount == trylim)
		{
			printf ("Recognized no echo replies from remote host after %i tries.\n", trylim);
			break;
		}
		
		sleep(1);
	}
	
	// Close socket descriptors.
	close (sendsd);
	close (recvsd);
	
	// Free allocated memory.
	free (src_mac);
	free (dst_mac);
	free (data);
	free (send_ether_frame);
	free (recv_ether_frame);
	free (target);
	free (dst_ip);
	free (rec_ip);
	free (ip_flags);
	
	return (EXIT_SUCCESS);
}
