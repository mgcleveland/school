/*-----------------------------------------------------------------------------
 * file: sr_pwospf.c
 * date: Tue Nov 23 23:24:18 PST 2004 
 * Author: Martin Casado
 *
 * Description:
 *
 *---------------------------------------------------------------------------*/

#include "sr_pwospf.h"
#include "sr_router.h"
#include "pwospf_protocol.h"

#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <malloc.h>
#include <string.h>

/* -- declaration of main thread function for pwospf subsystem --- */
static void* pwospf_run_thread(void* arg);

/*---------------------------------------------------------------------
 * Method: pwospf_init(..)
 *
 * Sets up the internal data structures for the pwospf subsystem 
 *
 * You may assume that the interfaces have been created and initialized
 * by this point.
 *---------------------------------------------------------------------*/

int pwospf_init(struct sr_instance* sr)
{
    assert(sr);

    sr->ospf_subsys = (struct pwospf_subsys*)malloc(sizeof(struct
                                                      pwospf_subsys));

    assert(sr->ospf_subsys);
    pthread_mutex_init(&(sr->ospf_subsys->lock), 0);
 
    /* -- handle subsystem initialization here! -- */
    sr->ospf_subsys->drt = NULL; 
    sr->ospf_subsys->dif = NULL;

    /* -- start thread subsystem -- */
    if( pthread_create(&sr->ospf_subsys->thread, 0, pwospf_run_thread, sr)) { 
        perror("pthread_create");
        assert(0);
    }

    return 0; /* success */
} /* -- pwospf_init -- */


/*---------------------------------------------------------------------
 * Method: pwospf_lock
 *
 * Lock mutex associated with pwospf_subsys
 *
 *---------------------------------------------------------------------*/

void pwospf_lock(struct pwospf_subsys* subsys)
{
  if ( pthread_mutex_lock(&subsys->lock) )
      { assert(0); }
} /* -- pwospf_subsys -- */

/*---------------------------------------------------------------------
 * Method: pwospf_unlock
 *
 * Unlock mutex associated with pwospf subsystem
 *
 *---------------------------------------------------------------------*/

void pwospf_unlock(struct pwospf_subsys* subsys)
{
    if ( pthread_mutex_unlock(&subsys->lock) )
    { assert(0); }
} /* -- pwospf_subsys -- */



/**************************************************************
 * Return the matching interface of a router connected to this
 * interface.  If none found, the default value is zero.
 **************************************************************/
uint32_t findAttachedInterface(dynif *dIf, uint32_t qIp, char *interface){

  dynif *walker = dIf;
  
  while(walker != NULL){

    /* if( walker->neighborRid.s_addr  == qIp ){ */
    if( strcmp(interface, walker->interface) == 0 ){
      /*fprintf(stderr, "RETURNING FROM findAttached....: ");*/
      printIp(walker->neighborRid.s_addr);
      return walker->neighborRid.s_addr;
    } else {
      /*printf("\t\t%X  VS  %X\n", walker->ourIp.s_addr, qIp);*/
    }

    walker = walker->next;
  }
  /*fprintf(stderr, "NO MATCHING INTERFACE FOUND FROM findAttached... ");*/
  return 0;
}





/*---------------------------------------------------------------------
 * Method: pwospf_run_thread
 *
 * Main thread of pwospf subsystem. 
 *
 *---------------------------------------------------------------------*/

void
printDrt(dynrt *drt) {

  if (drt == NULL) {
    printf("Drt is NULLL\n");
  }

  while (drt != NULL) {

    printf("---------------------------\n");
    printf(" Dest is : ");
    printIp(drt->dest.s_addr);
    printf(" Mask is: ");
    printIp(drt->mask.s_addr);
    printf("Gateway is: ");
    printIp(drt->gw.s_addr);
    printf("Via interface: %s\n", drt->interface);
    printf("TTL: %d NumHops: %d Seq# %d\n",
	   drt->ttl, drt->numHops, drt->lastSeqNumber);
    printf("---------------------------\n");

    drt = drt->next;

  }

}

uint32_t
getNextHopsIp(struct sr_instance *sr, char *interface) {
  uint32_t next;
  
  dynif *dif = sr->ospf_subsys->dif;
  while (dif != NULL) {
    if (strcmp( interface, dif->interface) == 0) {
      return dif->neighborIp.s_addr;
    }
    dif = dif->next;
  }

  struct sr_if *iflist = sr->if_list;
  while (iflist != NULL) {


    if ( strcmp(iflist->name, interface) == 0) {
      next = ntohl(iflist->ip); /* TODO: this is network order? */
      if (next % 2 != 0) {
	--next;
      } else {
	++next;
      }
      /*fprintf(stderr,
	"Terrible, yet awful is happening! %d\n", htonl(next));*/
      return htonl(next);
    }
  }

  /* 0 is not quite right... oh well */
  return 0;
}

/**************************************************
 * This uses the dynamic routing table, and looks up the query
 * it assumes that the query is in network byte order.
 **************************************************/
dynrt *
dynamicLongestPrefixMatch(uint32_t query, dynrt *drt){
  
  uint32_t i, j, mask, dest, longestMatch = 0, skip;
  dynrt *bestMatch = NULL;

  query = htonl(query);
  while (drt != NULL ) {
    skip = 0;
 
    dest = htonl(drt->dest.s_addr);
    mask = htonl(drt->mask.s_addr);

    if (drt->ttl) { /* only look at the entry if it's not timed out */

      for (j = 0; j < 32; ++j) {
	i = 1 << (31-j);
	/*       if the mask is set to 1 for the jth bit  */
	if ((i & mask) != 0) {
	  if ( (i & dest) != (i & query)) {
	    skip = 1; /* bits don't agree */
	    break; 
	  }
	} else 
	  break;
      }
      
      if (skip==0) {
	if ( j > longestMatch) {
	    if(bestMatch == NULL){
	      /*fprintf(stderr, "INITIALIZING dynamicLonges....\n");*/
	    }
	    else{
	      /*fprintf(stderr, "Better match found existing: %d  vs.  new:  %d  newj: %d  oldj = %d\n", bestMatch->numHops,
		drt->numHops, longestMatch, j);*/
	    }
	  longestMatch = j;
	  bestMatch = drt;

	} else if (j == longestMatch) {
	  /* if the prefix match is as large, favor the smaller number of hops */
	  if (bestMatch == NULL || bestMatch->numHops > drt->numHops){
	    if(bestMatch == NULL){
	      /*fprintf(stderr, "INITIALIZING dynamicLonges....\n");*/
	    }
	    else{
	      /*fprintf(stderr, "UPDATE: Better match found existing: %d  vs.  new:  %d  newj: %d  oldj = %d\n", bestMatch->numHops,
		drt->numHops, longestMatch, j);*/
	    }
	    bestMatch = drt;
	  }
	}
      }
    }
    drt = drt->next;
  }


  return bestMatch;
}



static
void* pwospf_run_thread(void* arg)
{
  /*printf("Entering run_thread\n");*/
  struct sr_instance* sr = (struct sr_instance*)arg;
  if(sr == NULL){
    fprintf(stderr, "SR is NULL!!!\n");
  }

  /* initialize the new packet to send */
  uint8_t packet[sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) 
		 + sizeof(struct ospfv2_hdr) + sizeof(struct ospfv2_lsu_hdr) 
		 + (sizeof(struct ospfv2_lsu) * MAX_INTERFACES)];

  struct sr_ethernet_hdr *ethHdr = (struct sr_ethernet_hdr*)packet;
  struct ip *ipHdr = (struct ip*)(packet + sizeof(struct sr_ethernet_hdr));
  struct ospfv2_hdr *ospfHdr = (struct ospfv2_hdr*)(packet + sizeof(struct ip) + 
						    sizeof(struct sr_ethernet_hdr));
  
  /* HELLO PACKET HEADER */
  struct ospfv2_hello_hdr *helloHdr = (struct ospfv2_hello_hdr*)(packet + sizeof(struct ospfv2_hdr) 
								 + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip));
  uint32_t helloLen = sizeof(struct sr_ethernet_hdr) + sizeof(struct ip)  
    + sizeof(struct ospfv2_hdr) + sizeof(struct ospfv2_hello_hdr);
  
  /* LSU packet headers */
  struct ospfv2_lsu_hdr *lsuHdr = (struct ospfv2_lsu_hdr*)(packet + sizeof(struct sr_ethernet_hdr) +
							   sizeof(struct ip) + sizeof(struct ospfv2_hdr));
  struct ospfv2_lsu *lsuPacket = (struct ospfv2_lsu*)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) +
						      sizeof(struct ospfv2_hdr) + sizeof(struct ospfv2_lsu_hdr));
  uint32_t lsuLen = sizeof(packet);
  
  /* clear packet */
  memset(packet, 0, lsuLen);

  /* set ethernet packet header values */
  ethHdr->ether_type = htons(ETHERTYPE_IP);
  
  /* set IP header values */
  ipHdr->ip_tos = 0;
  ipHdr->ip_id = 0;
  ipHdr->ip_off = htons(IP_DF);
  ipHdr->ip_ttl = DEFAULT_TTL;
  ipHdr->ip_p = OSPF_TYPE;
  ipHdr->ip_dst.s_addr = htonl(OSPF_AllSPFRouters);
  
  uint64_t time = 0, time2 = 0;
  dynrt *dynamicRt;
  dynif *dynamicIf;
  currSeq = 0;

  while(1){
    /* -- PWOSPF subsystem functionality should start  here! -- */
    pwospf_lock(sr->ospf_subsys);
    
    dynamicRt = sr->ospf_subsys->drt;
    dynamicIf = sr->ospf_subsys->dif;

    /* decrement TTL for dynamic routing table and 
       dynamic interface list */
    while (dynamicRt != NULL) {
      if (dynamicRt->ttl < 2)
	dynamicRt->ttl = TIME_EXPIRED;
      else
	--(dynamicRt->ttl);
      dynamicRt = dynamicRt->next;
    }

    while(dynamicIf != NULL){
      if(dynamicIf->helloInt < 2){
	if (dynamicIf->helloInt != OSPF_DEFAULT_LSUINT)
	  time2 = OSPF_DEFAULT_LSUINT;

	dynamicIf->helloInt = TIME_EXPIRED;
	
      }
      else
	--(dynamicIf->helloInt);
      dynamicIf = dynamicIf->next;
    }
    
    /*******************************************
     * Broadcast an OSPF HELLO packet
     *******************************************/
    if (time % OSPF_DEFAULT_HELLOINT == 0) {
      /*printf(" pwospf subsystem awake \n");*/
      
      struct sr_if *walker = sr->if_list;

      if(walker == NULL){
	/*fprintf(stderr, "WALKER IS NULL\n");*/
      }

      memset(ethHdr->ether_dhost, 255, ETHER_ADDR_LEN);
      while(walker != NULL){
	/* set eth header vals */
	memcpy(ethHdr->ether_shost, walker->addr, ETHER_ADDR_LEN);

	/* set IP header vals */
	ipHdr->ip_src.s_addr = walker->ip;
	ipHdr->ip_len = htons(helloLen - sizeof(struct sr_ethernet_hdr));

	/* IP checksum */
	uint8_t test = (0x4 << 4) | ( (sizeof(struct ip) >> 2)); 
	memcpy(ipHdr, &test, 1);
	/* test should be 0x45 ? that's what comes in. */
	ipHdr->ip_sum = 0;
	uint16_t ipCheckSum = calculateChecksum(ipHdr, sizeof(struct ip));
	ipHdr->ip_sum = ipCheckSum;

	/* set OSPF header vals */
	ospfHdr->version = 2;
	ospfHdr->type = OSPF_TYPE_HELLO;
	ospfHdr->len = htons(sizeof(struct ospfv2_hdr) + sizeof(struct ospfv2_hello_hdr));
	ospfHdr->rid = ipHdr->ip_src.s_addr;
	uint8_t aid = (uint8_t) ( ( ntohl(ipHdr->ip_src.s_addr) & 0xFF000000) >> 24);
	ospfHdr->aid = htonl(aid);

	/* hello packet vals */
	helloHdr->nmask = walker->mask;
	helloHdr->helloint = htons(OSPF_DEFAULT_HELLOINT);
	ospfHdr->csum = 0;
	uint16_t ospfCheckSum = calculateChecksum(ospfHdr, 
						  sizeof(struct ospfv2_hdr) + sizeof(struct ospfv2_hello_hdr));
	ospfHdr->csum = ospfCheckSum;
	/*fprintf(stderr, "Sending HELLO\n");*/
	/* send packet */
	sr_send_packet(sr, packet, helloLen, walker->name);

	/* iterate */
	walker = walker->next;
      }
    }
    
    /*********************************************
     * Broadcast an OSPF LSU packet
     *********************************************/
    if (time2 % OSPF_DEFAULT_LSUINT == 0) {
      
      struct sr_if *walker = sr->if_list;

      if(walker != NULL){
	/*fprintf(stderr, "MY WALKER IS ALSO NULL\n");*/

	ipHdr->ip_len = htons(helloLen - sizeof(struct sr_ethernet_hdr));
	
	/* set up OSPF header */
	ospfHdr->version = 2;
	ospfHdr->type = OSPF_TYPE_LSU;
	
	/* LSU header packet vals */
	lsuHdr->seq = htons(currSeq);
	lsuHdr->ttl = DEFAULT_TTL;
	
	/* loop variables */
	int numAttachedInterfaces = 0;
	uint32_t advertisementOffset = sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) + sizeof(struct ospfv2_hdr) + sizeof(struct ospfv2_lsu_hdr);
	
	while (walker != NULL) {
	  
	  /* set up LSU packet vals */
	  lsuPacket = (struct ospfv2_lsu*) 
	    (packet + numAttachedInterfaces*sizeof(struct ospfv2_lsu) +
	     advertisementOffset);
	  
	  /* set eth header vals */
	  /*memcpy(ethHdr->ether_shost, walker->addr, ETHER_ADDR_LEN);*/
	  
	  /* set IP header vals */
	  ipHdr->ip_src.s_addr = walker->ip;
	  ospfHdr->rid = (ipHdr->ip_src.s_addr);
	  uint8_t aid = (uint8_t) ( ( ntohl(ipHdr->ip_src.s_addr) & 0xFF000000) >> 24);
	  ospfHdr->aid = htonl(aid);
	  
	  /* LSU packet vals */
	  lsuPacket->subnet = walker->ip;
	  
	  uint32_t thisMask = walker->mask;
	  lsuPacket->mask = thisMask;
	  
	  /* This should be the RID of the router at the other 
	     end of this interface; if none yet exists, set it to 0 */
	  uint32_t tempRid = findAttachedInterface(sr->ospf_subsys->dif, 
						   lsuPacket->subnet, walker->name); 
	  lsuPacket->rid = tempRid;/*walker->ip;tempRid;*/
	  
	  ++numAttachedInterfaces;
	  walker = walker->next;
	}
	
	/* check if we've got a route to the Interweb */
	struct sr_rt* interWeb = sr->routing_table;
	while(interWeb != NULL){
	  if(interWeb->mask.s_addr == 0){  /* default route to internet */
	    uint8_t ourAid = (uint8_t) ( ( ntohl(ipHdr->ip_src.s_addr) & 0xFF000000) >> 24);
	    uint8_t gatewayId  =  (uint8_t) ( ( ntohl(interWeb->gw.s_addr) & 0xFF000000) >> 24);

	    if (ourAid == gatewayId)  /* if gw is not in our area, don't advertise it! */
	      interWeb = NULL;

	    break;
	  }
	  interWeb = interWeb->next;
	}

	/* if we have an interWeb connection, add it */
	if(interWeb != NULL){
	  
	  /* put in the if info from eth0 */
	  struct sr_if *runner = sr->if_list;

	  /* set up LSU packet vals */
	  lsuPacket = (struct ospfv2_lsu*) 
	    (packet + numAttachedInterfaces*sizeof(struct ospfv2_lsu) +
	     advertisementOffset);
	  
	  /* LSU packet vals */
	  lsuPacket->subnet = runner->ip;
	  
	  lsuPacket->mask = 0;
	  
	  /* This should be the RID of the router at the other 
	     end of this interface; if none yet exists, set it to 0 */
	  /*uint32_t tempRid = findAttachedInterface(sr->ospf_subsys->dif, 
	    lsuPacket->subnet, walker->name); */
	  lsuPacket->rid = 0; /*tempRid;walker->ip;tempRid;*/

	  ++numAttachedInterfaces;
	}

	/* set IP header vals */
	/*ipHdr->ip_src.s_addr = (walker->ip);*/
	uint32_t barf = (MAX_INTERFACES - numAttachedInterfaces) * (sizeof(struct ospfv2_lsu));
	ipHdr->ip_len = htons(lsuLen - barf - sizeof(struct sr_ethernet_hdr));

	/* set OSPF header len */
	ospfHdr->len = htons(lsuLen - barf 
			     - (sizeof(struct sr_ethernet_hdr) + sizeof(struct ip)));

	/* LSU header values */
	lsuHdr->num_adv = htonl(numAttachedInterfaces);

	/* test should be 0x45 ? that's what comes in. */
	/* IP checksum */
	uint8_t test = (0x4 << 4) | ( (sizeof(struct ip) >> 2)); 
	memcpy(ipHdr, &test, 1);
	ipHdr->ip_sum = 0;
	uint16_t ipCheckSum = calculateChecksum(ipHdr, sizeof(struct ip));
	ipHdr->ip_sum = ipCheckSum;

	/* set OSPF header check sum */
	ospfHdr->csum = 0;
	uint16_t ospfCheckSum = calculateChecksum(ospfHdr, 
						  sizeof(struct ospfv2_hdr) + sizeof(struct ospfv2_lsu_hdr) 
						  + (sizeof(struct ospfv2_lsu) * numAttachedInterfaces));
	ospfHdr->csum = ospfCheckSum;

	walker = sr->if_list;

	while(walker != NULL){
	  
	  memcpy(ethHdr->ether_shost, walker->addr, ETHER_ADDR_LEN);
	  memset(ethHdr->ether_dhost, 255, ETHER_ADDR_LEN);
	  /*fprintf(stderr, "Sending out some LSU packet action\n");*/
	  /* send packet */
	  sr_send_packet(sr, packet, lsuLen - barf, walker->name);
	  
	  /* iterate */
	  walker = walker->next;
	}
      } /* -- Is walker NULL? -- */
      ++currSeq;
      
    }/* -- LSU generation -- */
    
    pwospf_unlock(sr->ospf_subsys);
    sleep(1); /* matt and august changed this from "2" */
    
    ++time;
    ++time2;
  };
} /* -- run_ospf_thread -- */

