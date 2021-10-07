#ifndef PING_NEXT_HOP
#define PING_NEXT_HOP

// Define some constants.
#define ETH_HDRLEN 14  // Ethernet header length
#define IP4_HDRLEN 20  // IPv4 header length
#define ICMP_HDRLEN 8  // ICMP header length for echo request, excludes data

#define TRUE 1

#define UC	unsigned char 	
#define UI	unsigned int 	
#define US	unsigned short 	
#define UL	unsigned long

#define SIZE 50

// Function prototypes
uint16_t 	checksum 					(uint16_t *, int);
uint16_t 	icmp4_checksum 				(struct icmp, uint8_t *, int);
char 	*	allocate_strmem 			(int);
uint8_t *	allocate_ustrmem 			(int);
int 	*	allocate_intmem 			(int);
int 		validate_number				(char *str);
int 		validate_ip					(char *ip);
int 		Vaildate_URL				(UC *ip);
int 		remove_extra_spaces			(char *input);
int 		getWords					(char *base);
int 		Fetch_MAC_And_Interface		(UC *nextHOP_IP);
void 		Fetch_Interface_IP			(void);


#endif
