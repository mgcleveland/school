/**********************************************************************
 * file:  sr_router.c 
 * date:  Mon Feb 18 12:50:42 PST 2002  
 * Contact: casado@stanford.edu 
 *
 * Description:
 * 
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <net/ethernet.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <time.h>
#include <unistd.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "pwospf_protocol.h"
#include "sr_pwospf.h"

 /* the ARP cache  */
Arpcache arpcache[REALLYBIG];

/* the interface that represents "us" */
struct sr_if US;

/*struct sr_rt *longestPrefixMatch(uint32_t query, struct sr_rt *sr);*/

/**************************************************
 * ROUTER INITIALIZER
 **************************************************/
void sr_init(struct sr_instance* sr) 
{
    /* REQUIRES */
    assert(sr);
    int i;
    for (i = 0; i < REALLYBIG; ++i)
      arpcache[i].timeInSeconds = 0;
    
    setChecking(CLEAR);

    pwospf_init(sr); 
} /* -- sr_init -- */



/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/
void sr_handlepacket(struct sr_instance* sr, 
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
   /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);
    checkRT(sr);

    /* function-wide variables */
    struct sr_rt *routingTable = sr->routing_table; 
    struct sr_ethernet_hdr *etherpacket = (struct sr_ethernet_hdr*) packet;
    US = *(sr->if_list);

    /* grossly malformed packet */
    if (len < sizeof(struct sr_ethernet_hdr))
      return;

    /* check for odd-length packets */
    if(len % 2 != 0){
      fprintf(stderr, "Got and odd length packet.\n");
    }

    /**************************/
    /*    GOT AN IP PACKET    */
    /**************************/
    if (htons(ETHERTYPE_IP) == etherpacket->ether_type) {
      
      if (len < sizeof(struct sr_ethernet_hdr) + sizeof(struct ip))
	return;
  

      struct ip *iphdr = (struct ip*) (packet + sizeof(struct sr_ethernet_hdr));
      uint8_t clone[ sizeof(struct ip) + 8];
      uint32_t diff = len - sizeof(struct ip) - sizeof(struct sr_ethernet_hdr);
      /* make a deep copy of the incoming IP packet */
      if (diff < 8) {
	memcpy(clone, iphdr, sizeof(struct ip) + diff);
        memset( &clone[ sizeof(struct ip) + diff], 0, 8-diff); 
      } else 
        memcpy(clone, iphdr, sizeof(struct ip) + 8); 
      
      uint16_t oldcheck = iphdr->ip_sum;
      iphdr->ip_sum = 0; /* SO AS TO CALCULATE CORRECT CHECKSUM */
      uint16_t ipchecksum = calculateChecksum((void*)iphdr, sizeof(struct ip));
      iphdr->ip_sum = ipchecksum;
      
      /******************/
      /* CHECK CHECKSUM */
      /******************/
      if (ipchecksum != oldcheck && iphdr->ip_p != TCP_PROTOCOL && iphdr->ip_p != UDP_PROTOCOL) {
	printf("Dropping IP packet. Checksum mismatch: %u %u\n", 
	       ipchecksum, oldcheck);
	return; /* drop packet. bad checksum */
      }

      /********************************/
      /* FORWARD PACKET IF NOT FOR US */
      /********************************/
      struct sr_if *isUs = oneOfUs(sr->if_list, iphdr->ip_dst.s_addr);
      if(isUs == NULL){

	/*********************************************/
	/* PACKET HAS TIMED OUT, GENERATE ICMP ERROR */
	/*********************************************/
	if(iphdr->ip_ttl < 2){

	  /*printf("\t\t GENERATING ICMP VIA TTL \n");
	    printIp(iphdr->ip_dst.s_addr);*/

	  generateICMP(sr, iphdr->ip_src.s_addr, TIMEOUT_TYPE,
                       TIMEOUT_CODE, packet, arpcache, clone, interface, 0);
	  
	  if(getChecking() == CLEAR)
	    checkQueue(sr, routingTable, arpcache, &US);
	  
	  return;
	}

      
	/* DECREMENT TTL on IP packets not for us */
	iphdr->ip_ttl--;

	/* REGENERATE CHECKSUM for ICMP, NOT TCP/UDP*/
	if(IPPROTO_ICMP == iphdr->ip_p){
	  iphdr->ip_sum = 0; 
	  uint16_t ipchecksum2 = calculateChecksum((void*)iphdr, sizeof(struct ip));
	  iphdr->ip_sum = ipchecksum2;
	}
      } 
      
      /********************************/
      /*   IP PACKET IS ICMP TYPE     */
      /********************************/
      if (IPPROTO_ICMP == iphdr->ip_p) {

	if (len < sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) + sizeof(struct icmpPayload))
	  return;

        struct icmpPayload *icmp = (struct icmpPayload*) (packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip));

	/***********************************/
	/* IP/ICMP TYPE IS AN ECHO REQUEST */
	/***********************************/
        if (icmp->type == ECHO_REQUEST) {

	  /* ECHO REQUEST is NOT for us */
	  if (isUs == NULL) {

	    uint32_t index = checkArpcache(iphdr->ip_dst.s_addr, arpcache, sr);
	    
	    /* IP not in ARP cache */
	    if(index == -1){
	      /*fprintf(stderr, "ICMP ECHO REQUEST WAS NOT IN THE ARPCACHE\n");*/
	      add2queue(packet, len, iphdr->ip_dst.s_addr, interface, sr);
	    }
	    /* IP in ARP cache, forward to that MAC */
	    else{
	      struct sr_if *ifTemp = sr_get_interface(sr, arpcache[index].interface);
	      memcpy(etherpacket->ether_shost, ifTemp->addr, ETHER_ADDR_LEN);
	      memcpy(etherpacket->ether_dhost, arpcache[index].mac, ETHER_ADDR_LEN);

	      /*printf("\t\t MACS used to forward... shost, dhost");
	      printMac(etherpacket->ether_shost);
	      printMac(etherpacket->ether_dhost);
	      printf("from interface: %s\n", arpcache[index].interface);*/

	      sr_send_packet(sr, packet, len, arpcache[index].interface);
	    }
          } 
	  /* ECHO REQUEST is for us, respond with ECHO_REPLY*/
	  else {
	    
	    /* do checksumming */
	    oldcheck = icmp->checksum;
	    icmp->checksum = 0;
            uint16_t newcheck = calculateChecksum( (void*) icmp, 
						   len - (sizeof(struct sr_ethernet_hdr) + sizeof(struct ip)));
            
	    if (oldcheck != newcheck) {
	      printf("Icmp checksums disagree: %X %X\n", oldcheck, newcheck);
	      return;
            }

            icmp->type = ECHO_REPLY;
            icmp->checksum = 0;
	    icmp->checksum = calculateChecksum( (void*) icmp, 
						len - (sizeof(struct sr_ethernet_hdr) + sizeof(struct ip)));

	    /* ipheader fun */
   	    struct in_addr temp;
            temp.s_addr = isUs->ip;
            iphdr->ip_dst = iphdr->ip_src;
            iphdr->ip_src = temp;
	    iphdr->ip_ttl = DEFAULT_TTL; 
	    iphdr->ip_sum = 0;
	    iphdr->ip_sum = calculateChecksum( (void*) iphdr, sizeof(struct ip));

	    /*fprintf(stderr, "GOT AN ECHO REQUEST FOR US\n");*/

	    /* etherpacket header fun */
            memcpy( etherpacket->ether_dhost, etherpacket->ether_shost, ETHER_ADDR_LEN);
            memcpy( etherpacket->ether_shost, sr->if_list->addr, ETHER_ADDR_LEN);
	    
            sr_send_packet(sr, packet, len, sr->if_list->name);
          }
        } 
	/********************************/
	/* IP/ICMP TYPE IS AN ECHO REPLY */
	/********************************/
	else if (icmp->type == ECHO_REPLY) {
	  
	  /* ICMP_REPLY WAS NOT FOR US, FORWARD IT */
	  if(isUs == NULL){
	    /*fprintf(stderr, "FORWARDING ECHO REPLY\n");*/
	    uint32_t index = checkArpcache(iphdr->ip_dst.s_addr, arpcache, sr);
	    
	    /* generate arp request for un-indexed IP */
	    if(index == -1){/* && isApp == 0){*/
	      add2queue(packet, len, iphdr->ip_dst.s_addr, interface, sr);
	    } else
	      forwardPacket(sr, packet, len, iphdr->ip_dst.s_addr, &US, arpcache, index);

	  }
	  /* ECHO REPLY WAS FOR US */
	  else{
	    
	  }
	}
	/**************************************************/
	/*                                                */
	/**************************************************/
	else if(icmp->type == DEST_UNREACHABLE_TYPE){
	  struct sr_if *isUs = oneOfUs(&US, iphdr->ip_dst.s_addr);
	
	  /* TCP message for one of our interfaces, protocol unreachable */
	  if(isUs == NULL){
	    /* forward the packet, if not for us */
	    uint32_t index = checkArpcache(iphdr->ip_dst.s_addr, arpcache, sr);
	    
	    /* generate arp request for un-indexed IP */
	    if(index == -1){/* && isApp == 0){*/
	      add2queue(packet, len, iphdr->ip_dst.s_addr, interface, sr);
	    }
	    /* forward the packet, otherwise */
	    else{
	      forwardPacket(sr, packet, len, iphdr->ip_dst.s_addr,
			    &US, arpcache, index);
	    }
	  }
	}
	/**************************************/
	/* IP/ICMP TYPE WAS UNDEFINED, IGNORE */
	/**************************************/
	else {
	  struct sr_if *isUs = oneOfUs(&US, iphdr->ip_dst.s_addr);

	  if (isUs == NULL) {
	    /*printf("Port unreachable!\n");*/
	    uint32_t index = checkArpcache(iphdr->ip_dst.s_addr, arpcache, sr);

	    if(index == -1){
	      add2queue(packet, len, iphdr->ip_dst.s_addr, interface, sr);
	    }
	    else{
	    forwardPacket(sr, packet, len, iphdr->ip_dst.s_addr, &US,
			  arpcache, index);
	    }
	  }
	  /* generateICMP(sr, iphdr->ip_src.s_addr, DEST_UNREACHABLE_TYPE,
	     PORT_UNREACHABLE, packet, arpcache, clone, interface);*/
	  
        }
      }
      /***********************************************/
      /* IP TYPE WAS TCP                             */
      /***********************************************/
      else if(iphdr->ip_p == TCP_PROTOCOL){
	/*printf("Got a TCP packet!!!\n");*/
	struct sr_if *isUs = oneOfUs(&US, iphdr->ip_dst.s_addr);
	
	/* TCP message for one of our interfaces, protocol unreachable */
	if(isUs != NULL){
	  generateICMP(sr, iphdr->ip_src.s_addr, DEST_UNREACHABLE_TYPE,
		       PROTOCOL_UNREACHABLE, packet, arpcache, clone, interface, 0);
	}
	/* forward the packet, if not for us */
	else{
	  uint32_t index = checkArpcache(iphdr->ip_dst.s_addr, arpcache, sr);
	  
	  /* generate arp request for un-indexed IP */
	  if(index == -1){/* && isApp == 0){*/
	    /*fprintf(stderr, "TCP FORWARD ADDING TO QUEUE");*/
	    add2queue(packet, len, iphdr->ip_dst.s_addr, interface, sr);
	  }
	  /* forward the packet, otherwise */
	  else{
	    /*fprintf(stderr, "TCP FORWARD FORWARDING");*/
	    forwardPacket(sr, packet, len, iphdr->ip_dst.s_addr,
			  &US, arpcache, index);
	  }
	}
      }
      /***********************************************/
      /* IP TYPE WAS UDP                             */
      /***********************************************/
      else if(iphdr->ip_p == UDP_PROTOCOL) {
	/*printf("Got a UDP packet!!!\n");*/
	struct sr_if *isUs = oneOfUs(sr->if_list, iphdr->ip_dst.s_addr);
	
	/* TCP message for one of our interfaces, protocol unreachable */
	if(isUs != NULL){
	  /*
	    if (iphdr->ip_ttl < 2){
	    generateICMP(sr, iphdr->ip_src.s_addr, TIMEOUT_TYPE, 
			 TIMEOUT_CODE, packet, arpcache, clone, interface); 
	  }
	  
	  else{
	    generateICMP(sr, iphdr->ip_src.s_addr, DEST_UNREACHABLE_TYPE,
			 PORT_UNREACHABLE, packet, arpcache, clone, interface); 
			 }*/

	  if (iphdr->ip_ttl <= 2) {

	    generateICMP(sr, iphdr->ip_src.s_addr, DEST_UNREACHABLE_TYPE,
			 PORT_UNREACHABLE, packet, arpcache, clone, interface, iphdr->ip_dst.s_addr); 
	  }

	}
	/* forward the packet, if not for us */
	else{
	  uint32_t index = checkArpcache(iphdr->ip_dst.s_addr, arpcache, sr);
	  
	  /* generate arp request for un-indexed IP */
	  if(index == -1){/* && isApp == 0){*/
	    /*fprintf(stderr, "UDP FORWARD ADDING TO QUEUE");*/
	    add2queue(packet, len, iphdr->ip_dst.s_addr, interface, sr);
	  }
	  /* forward the packet, otherwise */
	  else{
	    /*	    struct sr_if *ifTemp = sr_get_interface(sr, arpcache[index].interface);

	    memcpy(etherpacket->shost, ifTemp->addr, ETHER_ADDR_LEN);
	    memcpy(etherpacket->dhost, arpcache[index].mac, ETHER_ADDR_LEN);
	    
	    fprintf(stderr, "UDP FORWARD FORWARDING");
	    sr_send_packet(sr, packet, len, arpcache[index].interface);*/
	    forwardPacket(sr, packet, len, iphdr->ip_dst.s_addr,
			  &US, arpcache, index);
	  }
	}
      }
      /***********************************************/
      /* OSPF IP TYPE                                */
      /***********************************************/
      else if(iphdr->ip_p == OSPF_TYPE) {


	uint32_t innerOffset = sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) + sizeof(struct ospfv2_hdr);

	/* Bad packet length, disregard */
	if( len < innerOffset ) {
	  fprintf(stderr, "Dropping packet: len is too small. %d vs %d\n", len, innerOffset);
	  return;
	}

	/*parse PWOSPF packet */
	struct ospfv2_hdr *ospfHdr = (struct ospfv2_hdr*) (packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip));
	
	/* check that version number is 2 */
	if(ospfHdr->version != 2) {
	  fprintf(stderr, "Dropping packet: ospf version is: %d\n", ospfHdr->version);
	  /*	  return; */
	}

	/* check that authentication types match */
	/* TODO: are these different checks?  */
	/* ensure auth type and data fields are zero */
	uint8_t aid = (uint8_t) ( ( ntohl(sr->if_list->ip) & 0xFF000000) >> 24);
	if( ospfHdr->autype != 0 || ospfHdr->audata != 0 ){
	  fprintf(stderr, "Dropping packet; bad AUTH values\n");
	  return;
	}

	/* check checksum of PWOSPF's packet contents (excluding 64-bit auth field */
	uint16_t oldCheckSum = ospfHdr->csum;
	ospfHdr->csum = 0;
	uint16_t ospfCheckSum = calculateChecksum(ospfHdr, 
						  (len - sizeof(struct sr_ethernet_hdr) - sizeof(struct ip)));

	if(ospfCheckSum != oldCheckSum){
	  fprintf(stderr, "OSPF checksum mismatch.  Aborting. %d vs %d\n",
		  oldCheckSum, ospfCheckSum);
	  return;
	}
	

	/* check that area ID matches our area ID */
	if ( aid  != ntohl(ospfHdr->aid)) {
	  fprintf(stderr, "Dropping packet; bad AID\n%u vs %u\n", aid, ntohl(ospfHdr->aid));
	  return;
	}

	/***************************************/
	/*     OSPF packet type was HELLO      */
	/***************************************/
	if(ospfHdr->type == OSPF_TYPE_HELLO){

	  /*fprintf(stderr, "GOT an ospf HELLO packet!\n");*/
	  struct ospfv2_hello_hdr *hello = (struct ospfv2_hello_hdr*) (packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) + sizeof(struct ospfv2_hdr));
	  
	  /* add this information to our ARP cache */
	  addToArpcache(iphdr->ip_src.s_addr, etherpacket->ether_shost, arpcache, sr, interface);
	  
	  dynif *ourDif = sr->ospf_subsys->dif;
	  dynif *prev = NULL;
	  
	  pwospf_lock(sr->ospf_subsys);

	  /* check to see if we have an iface for this HELLO packet */
	  while (ourDif != NULL) {

	    /* update the neighbor's entry, if found */
	    if(ospfHdr->rid == ourDif->neighborRid.s_addr &&
	       iphdr->ip_src.s_addr == ourDif->neighborIp.s_addr){
	      
	      ourDif->helloInt = OSPF_NEIGHBOR_TIMEOUT;
	      break;
	    }

	    prev = ourDif;
	    ourDif = ourDif->next;
	  }
	  
	  /* entry not found in our dynamic interface, add it */
	  if(ourDif == NULL){
	    dynif *add = (dynif*) malloc(sizeof(dynif));
	    
	    struct sr_if *ourIPFound = sr_get_interface(sr, interface);
	    add->ourIp.s_addr = ourIPFound->ip;/*ospfHdr->rid;*/
	    add->mask.s_addr = hello->nmask;
	    add->helloInt = OSPF_NEIGHBOR_TIMEOUT;
	    add->neighborRid.s_addr = ospfHdr->rid;
	    add->neighborIp.s_addr = ospfHdr->rid; /*iphdr->ip_src;*/
	    strcpy(add->interface, interface);
	    uint8_t *tempMac = getMacForInterface(sr, interface);
	    
	    if(tempMac != NULL){
	      memcpy(add->srcMac, tempMac, ETHER_ADDR_LEN);
	      memcpy(add->dstMac, etherpacket->ether_shost, ETHER_ADDR_LEN);
	      add->next = NULL;

	      /* initialize the list */
	      if (prev == NULL)
		sr->ospf_subsys->dif = add;
	      else /* or add to the list */
		prev->next = add;	    
	    }
	    else{
	      fprintf(stderr, "No matching interface found for dynif.\n");
	      free(add);
	    }
	  }
	  pwospf_unlock(sr->ospf_subsys);
	}
	/***************************************/
	/*     OSPF packet type was LSU        */
	/***************************************/
	else if(ospfHdr->type == OSPF_TYPE_LSU){
	  /*fprintf(stderr, "GOT an ospf LSU packet!\n");*/

	  if (len < sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) + sizeof(struct ospfv2_hdr) 
	      + sizeof(struct ospfv2_lsu) + sizeof(struct ospfv2_lsu_hdr))
	    return;
	  struct ospfv2_lsu_hdr *lsuHdr = (struct ospfv2_lsu_hdr*)(packet + sizeof(struct sr_ethernet_hdr) 
+ sizeof(struct ip) + sizeof(struct ospfv2_hdr));
	  struct ospfv2_lsu *lsuPacket = (struct ospfv2_lsu*)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) + sizeof(struct ospfv2_hdr) + sizeof(struct ospfv2_lsu_hdr));

	  
	  uint8_t advertise = 0;
	  uint16_t sequenceNum = ntohs(lsuHdr->seq);
	  uint32_t numAdvertisements = ntohl(lsuHdr->num_adv);
	  uint32_t advertisementOffset = sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) + sizeof(struct ospfv2_hdr) + sizeof(struct ospfv2_lsu_hdr);
	  
	  /* the sending address was us... that'd be bad */
	  if ( NULL != oneOfUs(sr->if_list, iphdr->ip_src.s_addr )) {
	    fprintf(stderr, "Dropping packet. Sent from us?!\n");
	    return;
	  }

	  pwospf_lock(sr->ospf_subsys);
	  int j;

	  for (j = 0; j < numAdvertisements; ++j, advertisementOffset += sizeof(struct ospfv2_lsu)) {
	    
	    lsuPacket = (struct ospfv2_lsu*) (packet + advertisementOffset);
	    /*fprintf(stderr, "Does this make sense?: Length is: %lu vs size of LSU: %lu\n",
		    len - (sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) + sizeof(struct ospfv2_hdr) + sizeof(struct ospfv2_lsu_hdr)) ,
		    sizeof(struct ospfv2_lsu));
		    fprintf(stderr, "Sequence number is: %u\n", sequenceNum); */
	    dynrt *prev = NULL, *drt = sr->ospf_subsys->drt;

	    while (drt != NULL) {
	    /* the message is redundant iff the originator of the message is the 
	       same, and if it arrived via the same interface */
	      /*fprintf(stderr, "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
	      fprintf(stderr, "Comparing drt's dest vs.  lsu's dest \n");
	      printIp(drt->dest.s_addr);
	      printIp(lsuPacket->subnet);
	      fprintf(stderr, "Comparing drt's mask vs.  lsu's mask \n");
	      printIp(drt->mask.s_addr);
	      printIp(lsuPacket->mask);
	      fprintf(stderr, "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");*/
	      if ((drt->dest.s_addr == lsuPacket->subnet)
		  && (drt->mask.s_addr == lsuPacket->mask) 
		  && (strcmp(drt->interface, interface) == 0) ){
	
		/*fprintf(stderr,"FOUND A DRT MATCH\n");*/
		break;
	      }
	      prev = drt;
	      drt = drt->next;
	    }

	    if (drt == NULL) { /* create a new packet */

	      dynrt *add = (dynrt*) malloc(sizeof(dynrt));
	      
	      add->dest.s_addr = lsuPacket->subnet;/*iphdr->ip_src; */
	      /*struct sr_if *ifaceLookup = sr_get_interface(sr, interface);*/
	      add->gw.s_addr = getNextHopsIp(sr, interface);

	      add->mask.s_addr = lsuPacket->mask;
	      strcpy(add->interface, interface);
	      /* TODO: CHECK TO SEE IF THIS IS YOUR NEIGHBOR */
	      add->ttl = OSPF_TOPO_ENTRY_TIMEOUT; 
	      add->next = NULL;
	      add->lastSeqNumber = ntohs(lsuHdr->seq); 

	      add->rid.s_addr = lsuPacket->rid;
	      add->numHops = DEFAULT_TTL - lsuHdr->ttl ;
	      advertise = 1;

	      if (sr->ospf_subsys->drt == NULL)
		sr->ospf_subsys->drt = add;
	      else{
		prev->next = add;
	      }

	    } 
	    /* update the info for this packet */
	    else if (drt->lastSeqNumber < sequenceNum){
	      
	      drt->dest.s_addr = lsuPacket->subnet;/*iphdr->ip_src;*/
	      drt->gw.s_addr = getNextHopsIp(sr, interface);
	      drt->mask.s_addr = lsuPacket->mask;
	      strcpy(drt->interface, interface);
	      drt->lastSeqNumber = sequenceNum;
	      drt->ttl = OSPF_TOPO_ENTRY_TIMEOUT;  
	      drt->rid.s_addr = lsuPacket->rid;
	      /* the distance between this router and the router 
		 that originated this message */
	      drt->numHops = DEFAULT_TTL - lsuHdr->ttl ;
	      advertise = 1;
	      
	    }
	    else{
	      printf("Ignoring LSU packet.\n");
	    }
	  }

	  pwospf_unlock(sr->ospf_subsys);	  

	  /* forward LSU updates, if database has changed */
	  if(advertise && lsuHdr->ttl > 1){
	    dynif *walker = sr->ospf_subsys->dif;

	    /* decrement the ttl, and recalc the checksums */
	    --(lsuHdr->ttl);
	    
	    while(walker != NULL){
	      
	      /* don't forward to originating interface */
	      if(strcmp(walker->interface, interface) == 0) {
		walker = walker->next;
		continue;
	      }
	      /* forward the packet if the ttl is valid and it exists in the dynrt */
	      if(walker->helloInt > 1){
		memcpy(etherpacket->ether_shost, walker->srcMac, ETHER_ADDR_LEN);
		memcpy(etherpacket->ether_dhost, walker->dstMac, ETHER_ADDR_LEN);
		iphdr->ip_dst = walker->neighborIp; 
		/* lsuPacket->subnet = walker->ip; */
		lsuPacket->mask = walker->mask.s_addr;

		iphdr->ip_sum = 0;
		iphdr->ip_sum = calculateChecksum(iphdr, sizeof(struct ip));
		
		ospfHdr->csum = 0;
		uint16_t ospfCheckSum = calculateChecksum(ospfHdr, 
							  (len - sizeof(struct sr_ethernet_hdr) - sizeof(struct ip)));
		ospfHdr->csum = ospfCheckSum;

		sr_send_packet(sr, packet, len, walker->interface);
	      }

	      walker = walker->next;
	    }
	  }
	}
	/***************************************/
	/*     OSPF packet type is undefined   */
	/***************************************/
	else{
	  fprintf(stderr, "Got and undefined OSPF packet type.\n");
	  return;
	}
      }
      /***********************************************/
      /* IP TYPE WAS UNDEFINED                       */
      /***********************************************/
      else{
      }
    } 
    /********************************/
    /*  GOT AN ETHERNET/ARP PACKET  */
    /********************************/
    else if (htons(ETHERTYPE_ARP) == etherpacket->ether_type) {

      struct sr_arphdr *arpheader = (struct sr_arphdr*) (packet + (sizeof(struct sr_ethernet_hdr)));

      /********************************************/
      /*  GOT AN ETHERNET/ARP ARP REQUEST PACKET  */
      /********************************************/
      if (htons(ARP_REQUEST) == arpheader->ar_op) {

        addToArpcache(arpheader->ar_sip, arpheader->ar_sha, arpcache, sr, interface);
	
	/* see if arp target is one of us (interfaces) */
	struct sr_if *walker = oneOfUs(&US, arpheader->ar_tip);

	/* ARP REQUEST was not for us */
        if (walker == NULL) {
	  uint32_t cIndex = checkArpcache(arpheader->ar_tip, arpcache, sr);
	  
	  /*  NOT IN CACHE, ADD TO ARP QUEUE */
	  if(cIndex == -1){
	    add2queue(packet, len, arpheader->ar_tip, interface, sr);
	  }
	  /* CACHE HIT, FORWARD TO TARGET IP */
	  else{
	    memcpy(etherpacket->ether_dhost, arpcache[cIndex].mac, ETHER_ADDR_LEN);
	    /*memcpy(etherpacket->ether_shost, walker->addr, ETHER_ADDR_LEN);*/
	    sr_send_packet(sr, packet, len, interface);
	  }
        } 
	/* ARP REQUEST was for us, send ARP_REPLY */
	else {
	  /*printf("\t\t GOT AN ARP REQUEST! SENDING A RESPONSE!\n");*/
 	  arpheader->ar_op = htons(ARP_REPLY);
          memcpy( arpheader->ar_tha, arpheader->ar_sha, ETHER_ADDR_LEN);
          memcpy( arpheader->ar_sha, walker->addr, ETHER_ADDR_LEN);
	  arpheader->ar_tip = arpheader->ar_sip;  
	  arpheader->ar_sip = walker->ip;
 
          memcpy(etherpacket->ether_dhost, etherpacket->ether_shost, ETHER_ADDR_LEN);
          memcpy(etherpacket->ether_shost, walker->addr, ETHER_ADDR_LEN);
          sr_send_packet(sr, packet, len, walker->name);
        }
      } 
      /********************************************/
      /*  GOT AN ETHERNET/ARP ARP REPLY PACKET    */
      /********************************************/
      else if (htons(ARP_REPLY) == arpheader->ar_op) {
	/* GOT AN ARP REPLY; ADD TO ARP CACHE */
        addToArpcache(arpheader->ar_sip, arpheader->ar_sha, arpcache, sr, interface);
      } 
      /********************************************/
      /*  GOT AN UNDEFINED ETHERNET/ARP PACKET    */
      /********************************************/
      else {
	fprintf(stderr, "Should never happen! Opcode: %u\n", arpheader->ar_op);
	return;
      }
    }
    /********************************************/
    /*  GOT A NON-IP, NON-ARP PACKET (UDP, TCP?)*/
    /*  WE DROP THIS PACKET                     */
    /********************************************/
    else {
      printf("Last catch!\n");
    }

    /* CHECK ARP QUEUE IF NOT ALREADY */
    if(getChecking() == CLEAR){
      checkQueue(sr, routingTable, arpcache, &US);
    }
}/* end sr_ForwardPacket */

