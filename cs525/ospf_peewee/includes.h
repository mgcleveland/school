
#ifndef INCLUDES_H
#define INCLUDES_H

#define IP 0
#define ARP 1

#define TCP_PROTOCOL 6
#define UDP_PROTOCOL 17

/* ICMP TYPEs */
#define ECHO_REPLY 0
#define DEST_UNREACHABLE_TYPE 3
#define ECHO_REQUEST 8
#define TIMEOUT_TYPE 11

#define REALLYBIG 1000
#define TIMEOUT 15
#define INTIAL_TRIES 5

#define CHECKING 0
#define CLEAR 1

#define FALSE 0
#define TRUE 1


/* ICMP CODEs */
#define TIMEOUT_CODE 0
#define DEST_UNREACHABLE 0
#define HOST_UNREACHABLE 1
#define PROTOCOL_UNREACHABLE 2
#define PORT_UNREACHABLE 3

#define DEFAULT_TTL 64


/* PWOSPF stuff */
#define OSPF_TYPE 89


/* includes */
#include "sr_rt.h"
#include "sr_router.h"
#include "pwospf_protocol.h"
#include "sr_pwospf.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

 /* variable to break recursive queue checkin */
uint8_t checking;

/**************************************************
 *
 **************************************************/
struct icmpPayload {
  uint8_t type;
  uint8_t code;
  uint16_t checksum;
  uint32_t quench;
  uint8_t data[ sizeof(struct ip) + 8];
}__attribute__ ((packed));



/**************************************************
 *
 **************************************************/
typedef struct {
  char interface[sr_IFACE_NAMELEN];
  uint32_t ip;
  uint8_t  mac[ETHER_ADDR_LEN];
  unsigned long timeInSeconds;
} Arpcache;



/**************************************************
 *
 **************************************************/
typedef struct arpqueue {
  uint16_t type;
  uint32_t ip, len;
  uint8_t *packet;
  uint32_t remainingTries;
  char interface[sr_IFACE_NAMELEN];
  unsigned long timeInSeconds;
  struct arpqueue *next;
} Arpqueue;



/**************************************************
 * PROTOTYPES
 **************************************************/
void removeFromQueue(uint32_t i);
void generateICMP(struct sr_instance *sr, uint32_t destIp, 
                  uint8_t pType, uint8_t pCode, uint8_t *packet,
		  Arpcache *arpcache, uint8_t *original, char *interface, uint32_t srcIp);

/* uses the static routing table */
struct sr_rt *
longestPrefixMatch(uint32_t query, struct sr_rt *sr);


/**************************************************
 * Checksum function one
 *  Len is in bytes 
 *  From: page 95 of Peterson and Davie 
 **************************************************/
uint16_t
calculateChecksum(void *header, uint32_t len);


/**************************************************
 * Checksum function two
 *  Len is in bytes 
 *  From: page 95 of Peterson and Davie 
 **************************************************/
uint16_t
checksum2(void *buf, uint32_t len);

/**************************************************
 * USED TO PREVENT RECURSIVE QUEUE CHECKING
 **************************************************/
int getChecking();

void setChecking(int v);

/***************************************************************************
 *
 ***************************************************************************/
void
add2queue(uint8_t *packet, uint32_t len, 
	  uint32_t ip, char *interface, struct sr_instance *sr);

/***************************************************************************
 *
 ***************************************************************************/
void
addToArpcache(uint32_t ip, uint8_t *mac, Arpcache *arpcache, struct sr_instance *sr, char *);

/**************************************************
 *
 **************************************************/
uint32_t
checkArpcache(uint32_t quip, Arpcache *arpcache, struct sr_instance *sr);

/**************************************************
 * removes the ith entry from the arpqueue
 **************************************************/
void
removeFromQueue(uint32_t i);

/**************************************************
 *
 **************************************************/
void printMac(unsigned char *mac);

/*--------------------------------------------------------------------- 
 * Method:
 *
 *---------------------------------------------------------------------*/
void printIp(uint32_t ip);

/***************************************************
 * Takes in an sr_instance and an IP in *network byte order
 * and broadcasts out an ARP request
 ***************************************************/
void
sendArpRequest(struct sr_instance *sr, uint32_t ipAddress);

/**************************************************
 *
 **************************************************/

/***************************************************************************
 *
 ***************************************************************************/
struct sr_if *checkInterfaces(char *myIF, struct sr_instance *sr);

/****************************************************************
 *Walks down the queue. If the counter is 0, it frees the memory
 *and sends 
 ****************************************************************/
void
checkQueue(struct sr_instance *sr, struct sr_rt *routingTable, 
	   Arpcache *arpcache, struct sr_if *US);

/***************************************************************************
 *
 ***************************************************************************/
void forwardPacket(struct sr_instance *_sr, uint8_t *_packet, 
		   int _len, uint32_t _dstIp, struct sr_if *US,
		   Arpcache *arpcache, uint32_t index);

/***************************************************************************
 * Return interface matching dIp, NULL if none found
 ***************************************************************************/
struct sr_if *oneOfUs(struct sr_if *US, uint32_t dIp);

/**************************************************
 *
 **************************************************/
void checkRT(struct sr_instance *sr);


/**************************************************
 *
 **************************************************/
void printHello(struct ospfv2_hello_hdr *head);


/**************************************************
 *
 **************************************************/
uint8_t *getMacForInterface(struct sr_instance *sr, char *interface);



#endif
