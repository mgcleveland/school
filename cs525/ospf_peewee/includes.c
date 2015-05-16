#include "includes.h"

/*   our ARP queue  */
Arpqueue *arpqueue = NULL;

uint16_t
calculateChecksum(void *header, uint32_t len) {
  uint32_t answer = 0;
  uint16_t *stream = (uint16_t*) header;
  uint32_t i, stop = len / 2;
  for (i = 0; i < stop; ++i) {
    answer += *stream;
    if (answer & 0xFFFF0000) {
      answer &= 0xFFFF;
      ++answer;
    }
    ++stream;
  }

  /* odd number of bytes. goody */
  if (len % 2) {
    uint8_t byte;
    memcpy(&byte, stream, 1);
    answer += byte;
   
    if (answer & 0xFFFF0000) {
      answer &= 0xFFFF;
      ++answer;
    }
  }
  
  return ~(answer & 0xFFFF); /* and flip the bits */
}


/**************************************************
 * Checksum function two
 *  Len is in bytes 
 *  From: page 95 of Peterson and Davie 
 **************************************************/
uint16_t
checksum2(void *buf, uint32_t len) {

  len /= 2;
  uint16_t *data = (uint16_t*) buf;
  uint32_t answer = 0;

  while (len--) {
    answer += *data;
    ++data;
  }
  
  while (answer >> 16)
	answer = (answer & 0xffff) + (answer >> 16);

  return ~answer;
}


/**************************************************
 * USED TO PREVENT RECURSIVE QUEUE CHECKING
 **************************************************/
int getChecking(){
  return checking;
}

void setChecking(int v){
  checking = v;
}




/***************************************************************************
 *
 ***************************************************************************/
void
add2queue(uint8_t *packet, uint32_t len, 
	  uint32_t ip, char *interface, struct sr_instance *sr) {

  int queueLen = 0;
  int gotMatch   = 0;
  Arpqueue *tmp = arpqueue;

  if (arpqueue == NULL) {
    arpqueue = (Arpqueue*) malloc(sizeof(Arpqueue));
    if (arpqueue == NULL) {
      fprintf(stderr, "Malloc error\n");
      exit(1);
    }
    tmp = arpqueue;
  } 
  else{
    
    while (tmp->next != NULL) {
      if (tmp->ip == ip || tmp->next->ip == ip) {
	gotMatch = 1;
      }
      tmp = tmp->next;
      queueLen++;
    }

    tmp->next = (Arpqueue*) malloc(sizeof(Arpqueue));
    if (tmp->next == NULL) {
      fprintf(stderr, "Malloc error\n");
      exit(1);
    }
    tmp = tmp->next;
  }
  tmp->ip = ip;
  tmp->len = len;
  tmp->packet = (uint8_t*) malloc(len);
  strcpy(tmp->interface, interface);
  tmp->remainingTries = INTIAL_TRIES-1;
  tmp->timeInSeconds = time(NULL); 
  if (tmp->packet == NULL) {
    fprintf(stderr, "Malloc error\n");
    exit(1);  
  }
  memcpy( tmp->packet, packet, len);
  tmp->next = NULL;

  /* ensure that the initial ARP request for this IP happens now... */
  if(! gotMatch) {
    sendArpRequest(sr, ip);
  }


  /*fprintf(stderr, "Queue length: %d\n", queueLen);*/
}



/***************************************************************************
 *
 ***************************************************************************/
void
addToArpcache(uint32_t ip, uint8_t *mac, Arpcache *arpcache, struct sr_instance *sr, char *interface) {

  unsigned long min = -1, i, j=0, seconds = time (NULL);
  uint8_t found = FALSE;
  /*
  struct sr_rt *best = longestPrefixMatch(ip, sr->routing_table);

  if (best->gw.s_addr != 0)
    ip = best->gw.s_addr;
  else 
    ip = best->dest.s_addr;
  */

  uint8_t qaid =  (uint8_t) ( ( ntohl(ip) & 0xFF000000) >> 24);
  uint8_t oaid = (uint8_t) ( (ntohl(sr->if_list->ip)) >> 24);

  for (i = 0; i < REALLYBIG; ++i) {
    if(memcmp(mac, arpcache[i].mac, ETHER_ADDR_LEN) == 0){

      
      if (qaid != oaid) {
	arpcache[i].timeInSeconds = time (NULL);

      }
      found = TRUE;
      break;
    }
    else if (seconds - arpcache[i].timeInSeconds > TIMEOUT && 
	     arpcache[i].timeInSeconds != -1) {
      j = i;
      break; /* a HACK. get rid of the stalest entry if all else fails */
    } else if ( min > arpcache[i].timeInSeconds ) {
      j = i;
      min = arpcache[i].timeInSeconds;
    }
  }


  /* 0th entry CANNOT time out (that's the firewall */
  if(!found){

    strcpy(arpcache[j].interface, interface);
    arpcache[j].ip = ip;
    memcpy( arpcache[j].mac, mac, ETHER_ADDR_LEN);

    /* different area ids */
    if (qaid != oaid)
      arpcache[j].timeInSeconds = -1;
    else
      arpcache[j].timeInSeconds = time (NULL);

    /*    fprintf(stderr, "ARPCACHE: Adding to index: %lu interface: %s time is: %lu\n"
	  , j, interface, arpcache[j].timeInSeconds);    
    printIp(ip);
    printMac(mac);*/

  }
}



/**************************************************
 *
 **************************************************/
uint32_t
checkArpcache(uint32_t quip, Arpcache *arpcache, struct sr_instance *sr) {
  uint32_t i, isApp = 0;

  dynrt *bestDynamic = dynamicLongestPrefixMatch(quip, sr->ospf_subsys->drt);
  struct sr_rt *bestStatic;
  
  struct sr_if *nextHop = sr->if_list;

  unsigned long seconds = time(NULL);

  /* attempt a naive search first */
  for (i= 0; i < REALLYBIG; ++i) {
    if (arpcache[i].timeInSeconds == 0) {
      break;
    } else if (seconds - arpcache[i].timeInSeconds <= TIMEOUT) {
      /* if the quip is attached to us, there's no other route, so just return it */
      if (arpcache[i].ip == quip) {
	/*fprintf(stderr, "NAIVE SEARCH WORKED \n");*/
	return i;
      }
    } 
  }

  if(bestDynamic == NULL){
    bestStatic = longestPrefixMatch(quip, sr->routing_table);
    if (bestStatic == NULL) /* TODO: May need to drop the packet! this won't do that */
      return -1;

    /*printf("STATIC MAPPING! Gateway, dest, orig\t\n ");
    printIp(bestStatic->gw.s_addr);
    printIp(bestStatic->dest.s_addr);
    printIp(quip);*/

    
    nextHop = sr_get_interface(sr, bestStatic->interface);
  } else {

    uint32_t mask = ntohl(bestDynamic->mask.s_addr);
    uint32_t max = -1;
    
    /* if the longest prefix match is the default route (mask is 0), check the static interface list */
    if (max - mask > 2) {
      while (nextHop != NULL) {
	if  ((nextHop->ip & nextHop->mask) == (quip & nextHop->mask)) {
	  isApp = 1;
	  /*fprintf(stderr, "GOT AN APP SERVER! WAITING ON AN ARP\t\t");*/
	  /*printIp(quip);
	    printIp(nextHop->ip);*/
	  return -1;
	}
	nextHop = nextHop->next;
      }
    }

    /*printf("Trying to find ip:\t\t\t");
    printIp(quip);
    printf("dynamic mask is: \t\t\t");
    printIp(bestDynamic->mask.s_addr);
    printf("dynamic nextHop is: \t\t\t");
    printIp(bestDynamic->gw.s_addr);*/

    /* definitely not an APP server */
    if (nextHop == NULL) {
      /*printf("\t\t Got a dynamic routing table match out of Iface: %s  \t",
	bestDynamic->interface);
	printIp(quip);*/
      nextHop = sr_get_interface(sr, bestDynamic->interface);
    }
  }

  if (nextHop == NULL) {
    /*    if (bestDynamic == NULL)
      fprintf(stderr, "This should NEVER happen: No next hop for iface: %s\n", bestStatic->interface);
    else
    fprintf(stderr, "This should NEVER happen: No next hop for iface: %s\n", bestDynamic->interface);*/
    return -1;
  }

  /* if you're here, then one of the two bests is not NULL */

  

  for (i = 0; i < REALLYBIG; ++i) {

    /* outer */
    if (arpcache[i].timeInSeconds == 0) {
      /*fprintf(stderr, "THE ARPCACHE ENTRY HAS TIMED OUT at index %d\n", i);*/
      return -1;
    } 
    /* outer*/
    else if ( seconds - arpcache[i].timeInSeconds <= TIMEOUT ) { /* entry hasn't timed out */
      /* inner */
      if (isApp) {
	/*fprintf(stderr, "IS AN APP SERVER! WOOT!\n");*/
	if (arpcache[i].ip == quip) {
	  return i;
	}
      }
      /* inner */
      else if (bestDynamic == NULL) {
	
	if (bestStatic->gw.s_addr == 0) { /* gateway is the next hop */ 
	  if ( (bestStatic->dest.s_addr & nextHop->mask) == (arpcache[i].ip & nextHop->mask) ) {
	    /*fprintf(stderr, "HERE I AM! HIT IS THE NEXT HOP IN THE STATIC MOFO\n");*/
	    return i;
	  }
	} 
	else if ( (arpcache[i].ip & nextHop->mask) == (bestStatic->gw.s_addr & nextHop->mask)) { /* MAY NEED TO BE &MASK ...? */
	  /*fprintf(stderr, "Got a CACHE HIT in the static routing table\n");*/
	  return i;
	}
      } 
      /* inner */
      else {
	if (arpcache[i].ip == bestDynamic->gw.s_addr) {
	  /*fprintf(stderr, "Got a CACHE HIT in the dynamic routing table\n");*/
	  return i;
	}
      }
    }
  }


  return -1;
}



/**************************************************
 * removes the ith entry from the arpqueue
 **************************************************/
void
removeFromQueue(uint32_t i) {

  /*fprintf(stderr, "Removing index: %d from queue\n", i);*/
 
  Arpqueue *tmp, *prev;
  if (i == 0) {
    tmp = arpqueue->next;
    free(arpqueue->packet);
    free(arpqueue);
    arpqueue = tmp;
  } else {
   tmp = arpqueue;
   while (i) {
     prev = tmp;
     tmp = tmp->next;
     --i;
   }
   free(tmp->packet);
   prev->next = tmp->next;
   free(tmp);
  }
}


/**************************************************
 *
 **************************************************/
void printMac(unsigned char *mac){

  int i;
  for(i = 0; i<ETHER_ADDR_LEN; i++){
    printf("%X ", mac[i]);
  }
  
  printf("\n");
}


/*--------------------------------------------------------------------- 
 * Method:
 *
 *---------------------------------------------------------------------*/
void printIp(uint32_t ip) {
  int one, two, three, four;
  one = ip % 256;
  ip /= 256;
  two = ip % 256;
  ip /= 256;
  three = ip % 256;
  ip /= 256;
  four = ip % 256;

  printf("%u %u %u %u\n", four, three, two, one);
}




/***************************************************
 * Takes in an sr_instance and an IP in *network byte order
 * and broadcasts out an ARP request
 ***************************************************/
void
sendArpRequest(struct sr_instance *sr, uint32_t ipAddress) {


  /*printf("ARP!!!! original IP: ");
    printIp(ipAddress);*/

  uint8_t junk[ sizeof(struct sr_arphdr) + sizeof(struct sr_ethernet_hdr)];
  dynrt *dynamicRt = dynamicLongestPrefixMatch(ipAddress, sr->ospf_subsys->drt);
  if (dynamicRt == NULL) {
    struct sr_rt *best = longestPrefixMatch(ipAddress, sr->routing_table);
    if (best == NULL)
      return;

    if (best->gw.s_addr != 0)
      ipAddress = best->gw.s_addr;
  
  } else {


    uint32_t mask = ntohl(dynamicRt->mask.s_addr);
    uint32_t max = -1;
    struct sr_if *nextHop = sr->if_list;
  /* if the longest prefix match is the default route (mask is 0), check the static interface list */
    if (max - mask > 2) {

      while (nextHop != NULL) {
	if  ((nextHop->ip & nextHop->mask) == (ipAddress & nextHop->mask)) {
	  /*fprintf(stderr, "SENDING ARP TO APP SERVER (not remapping IP)\t\t");
	  printIp(ipAddress);
	  printIp(nextHop->ip);*/
	  
	  break;
	}
	nextHop = nextHop->next;
      }
      
    }
    if(nextHop == NULL) {
      ipAddress = dynamicRt->gw.s_addr;
      if (ipAddress == 0)
	return;
    }
  }

  /*printf("Arp!!!!! remapped IP: ");*/
  printIp(ipAddress);

  /* zero out the packet */
  memset(junk, 0, sizeof(struct sr_arphdr) + sizeof(struct sr_ethernet_hdr) );

  struct sr_if *walker = sr->if_list;

  if (walker == NULL) {
    fprintf(stderr, "Error in sendArpRequest: if_list is NULL!\n");
    return;
  }

  struct sr_ethernet_hdr *etherpacket = (struct sr_ethernet_hdr*) junk;
  struct sr_arphdr *arpheader = (struct sr_arphdr*) (junk + sizeof(struct sr_ethernet_hdr));

  /* request type */
  etherpacket->ether_type = htons(ETHERTYPE_ARP);
  arpheader->ar_op = htons(ARP_REQUEST);

  /* arp ip  */
  arpheader->ar_tip = ipAddress;
  arpheader->ar_sip = walker->ip;

  /* send to the broadcast ethernet address */
  memset(etherpacket->ether_dhost, 255, ETHER_ADDR_LEN);
  memcpy(arpheader->ar_sha, walker->addr, ETHER_ADDR_LEN);
  /* constants from the arp header that the firewall sent to us... */
  arpheader->ar_hrd = htons(0x1);
  arpheader->ar_pro = htons(0x800);
  arpheader->ar_hln = 0x6;
  arpheader->ar_pln = 0x4;
  while (walker != NULL) {

    memcpy( etherpacket->ether_shost, walker->addr, ETHER_ADDR_LEN);

    sr_send_packet(sr, junk,
		   sizeof(struct sr_arphdr) + sizeof(struct sr_ethernet_hdr), walker->name);
    walker = walker->next;
  }

}




/**************************************************
 *
 **************************************************/
void generateICMP(struct sr_instance *sr, uint32_t destIp,
                  uint8_t pType, uint8_t pCode, uint8_t *packet,
		  Arpcache *arpcache, uint8_t *original, char *interface, uint32_t sourceIp) {

  /*printf("IN generate ICMP");*/
 
  uint8_t data[  sizeof(struct ip) + sizeof(struct sr_ethernet_hdr) +
                 sizeof(struct icmpPayload) ];

  /* zero out the packet */
  memset(data, 0, sizeof(struct ip) + sizeof(struct sr_ethernet_hdr) +
         sizeof(struct icmpPayload));

  /* parse ethernet headers from original packet and our new one */
  struct sr_ethernet_hdr *origEthHeader = (struct sr_ethernet_hdr*)packet;
  struct sr_ethernet_hdr *ethHeader = (struct sr_ethernet_hdr*)data;

  /* Swap ethernet targets */
  memcpy(ethHeader->ether_shost, origEthHeader->ether_dhost, ETHER_ADDR_LEN);
  memcpy(ethHeader->ether_dhost, origEthHeader->ether_shost, ETHER_ADDR_LEN);
  ethHeader->ether_type = htons(ETHERTYPE_IP);

  struct ip *ipHeader = (struct ip*)(data + sizeof(struct sr_ethernet_hdr));
  ipHeader->ip_tos = 0;
  struct sr_if *ifMatch = sr_get_interface(sr, interface);
  
  /*unsigned char tempLen = htons(sizeof( struct ip) + sizeof(struct icmpPayload)); MAY NEED TO CHANGE */
  ipHeader->ip_len = htons(sizeof(struct icmpPayload) + sizeof(struct ip));/*(tempLen * 4) */
  ipHeader->ip_id = 0; /* MAY NEED TO CHANGE */
  ipHeader->ip_off = htons(IP_DF);
  ipHeader->ip_ttl = DEFAULT_TTL;
  ipHeader->ip_p = IPPROTO_ICMP;


  if (sourceIp)
    ipHeader->ip_src.s_addr = sourceIp;
  else
    ipHeader->ip_src.s_addr = ifMatch->ip;
 
  ipHeader->ip_dst.s_addr = destIp;

  /*printf("Source interface: %s\tSource ip:\n", interface);
  printIp(ifMatch->ip);
  printMac(ethHeader->ether_shost);*/
  
  uint8_t test = (0x4 << 4) | ( (sizeof(struct ip) >> 2)); 
  memcpy(ipHeader, &test, 1);
  /* test should be 0x45 ? that's what comes in. */
  

  /*
  if (pCode == PORT_UNREACHABLE) {
    struct ip *origIphdr = (struct ip*) (packet + sizeof(struct sr_ethernet_hdr));
    ipHeader->ip_src.s_addr = origIphdr->ip_dst.s_addr;
    }*/

  ipHeader->ip_sum = 0;
  uint16_t myChecksum = calculateChecksum(ipHeader, sizeof(struct ip));
  /* DO CHECKSUM AFTER POPULATING ALL DATA */
  ipHeader->ip_sum = myChecksum;
  
  struct icmpPayload *icmpHeader = (struct icmpPayload*)(data +
                                                         sizeof(struct sr_ethernet_hdr)
                                                         + sizeof(struct ip));
  icmpHeader->type = pType;
  icmpHeader->code = pCode;
  icmpHeader->quench = 0;

  /* QUENCH IS INTERNET HEADER PLUS FIRST 64 BITS OF ORIGINAL DATAGRAM'S DATA */
  memcpy(icmpHeader->data, original,
         (sizeof(struct ip) + 8));

  icmpHeader->checksum = 0;
  uint16_t icmpChecksum = calculateChecksum(icmpHeader, sizeof(struct icmpPayload));
  icmpHeader->checksum = icmpChecksum;

  /*printf("%X is the header length\n", (uint8_t) icmpHeader->data[0]);*/

  sr_send_packet(sr, data,
                 sizeof(struct ip) + sizeof(struct sr_ethernet_hdr) + sizeof(struct icmpPayload), ifMatch->name); /*"eth0"*/
}

/***************************************************************************
 *
 ***************************************************************************/
struct sr_if *checkInterfaces(char *myIF, struct sr_instance *sr){

  int found = FALSE;

  struct sr_if *ifTemp = sr->if_list;

  do{
    if(strcmp(ifTemp->name, myIF) == 0){
      found = TRUE;
      break;
    }      
  }while( ((!found) && (ifTemp = ifTemp->next)) );
  
  if(found){
    return ifTemp;
  }
  else{
    return NULL;
  }
}



/****************************************************************
 *Walks down the queue. If the counter is 0, it frees the memory
 *and sends 
 ****************************************************************/
void
checkQueue(struct sr_instance *sr, struct sr_rt *routingTable, 
	   Arpcache *arpcache, struct sr_if *US) {
  
  checking = CHECKING;
  uint32_t i, cacheIndex, queueIndex = 0, lazyArp[REALLYBIG], currQueueSize = 0;
  Arpqueue *tmp = arpqueue;
  unsigned long seconds = time(NULL);


  if (tmp == NULL){
    checking = CLEAR;
    return;
  }

  while (tmp != NULL) {


    if (tmp->remainingTries) {

      cacheIndex = checkArpcache(tmp->ip, arpcache, sr);
      /*printf("Remaining tries: %d ; index: %d\n", tmp->remainingTries, cacheIndex);
	printIp(tmp->ip);*/
      /* GOT A CACHE HIT */
      if (cacheIndex != -1) { /* TODO: send arp REPLY (ICMP ECHO?) */
	sr_handlepacket(sr, tmp->packet, tmp->len, tmp->interface);
        tmp = tmp->next;
        removeFromQueue(queueIndex); /* frees the memory */
	continue;
      }
      /* GOT A CACHE MISS */
      else{
	/* send out an ARP request for this ip */
        if (seconds - tmp->timeInSeconds > 0) {
	  --(tmp->remainingTries);

	  for (i = 0; i < currQueueSize; ++i)
	    if (lazyArp[i] == tmp->ip)
	      break;
	  
  /* send out an ARP request ONLY if we have not sent one out on this round of checking */
	  if (i == currQueueSize) {
	  
	    sendArpRequest(sr, tmp->ip);
	    /*printf("New ip ?!\n");
	      printIp(tmp->ip);*/

	    lazyArp[i] = tmp->ip;
	    currQueueSize++;
	  } 


	  
	  tmp->timeInSeconds = seconds;
        }
      }
    } else { /* TODO: Send host ICMP host unreachable */
      
      /* interpolate what the original IP packet was */
      uint8_t clone[ sizeof(struct ip) + 8];
      memset(clone, 0, sizeof(struct ip) + 8);
      
      struct ip *data;
      memcpy(clone, &(tmp->packet[sizeof(struct sr_ethernet_hdr)]),
			sizeof(struct ip) + 8);
      data = (struct ip*) clone;
      data->ip_ttl += 1;
      data->ip_sum = 0;
      /* TODO: htons the sum? */
      data->ip_sum = calculateChecksum(data, sizeof(struct ip));
      
      struct sr_ethernet_hdr *eth = (struct sr_ethernet_hdr*) tmp->packet;
      if (eth->ether_type == htons(ETHERTYPE_IP)) {
	struct ip *ipHeader = (struct ip*)(tmp->packet + sizeof(struct sr_ethernet_hdr));
	struct sr_rt *rtMatch = longestPrefixMatch(ipHeader->ip_src.s_addr, sr->routing_table);

	generateICMP(sr, tmp->ip, DEST_UNREACHABLE_TYPE,
		     HOST_UNREACHABLE, tmp->packet, arpcache, clone, rtMatch->interface, 0);
      }
      else if (eth->ether_type == htons(ETHERTYPE_ARP)) {
	struct sr_arphdr *arp = (struct sr_arphdr*) (tmp->packet + sizeof(struct sr_ethernet_hdr));
	struct sr_rt *rtMatch = longestPrefixMatch(arp->ar_sip, sr->routing_table);
	generateICMP(sr, tmp->ip, DEST_UNREACHABLE_TYPE,
		     HOST_UNREACHABLE, tmp->packet, arpcache, clone, rtMatch->interface, 0);
      }
      tmp = tmp->next;
      removeFromQueue(queueIndex);
      continue;
    }
    tmp = tmp->next;
    ++queueIndex;
  }

  checking = CLEAR;
}



/***************************************************************************
 *
 ***************************************************************************/
void forwardPacket(struct sr_instance *_sr, uint8_t *_packet, 
		   int _len, uint32_t _dstIp, struct sr_if *US,
		   Arpcache *arpcache, uint32_t index){

  struct sr_ethernet_hdr *ethHdr = (struct sr_ethernet_hdr*) _packet;
  struct ip *ipHdr = (struct ip*) (_packet + sizeof(struct sr_ethernet_hdr));
  struct icmpPayload *icmp = (struct icmpPayload*)
    (_packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip));
  
  /*
    struct sr_rt *rtTemp = longestPrefixMatch(_dstIp, RT);
    struct sr_if *ifMatch = checkInterfaces(rtTemp->interface, _sr);
  */
  struct sr_if *ifMatch = sr_get_interface(_sr, arpcache[index].interface);

  /*fprintf(stderr, "FORWARDING PACKET OUT OF ARPCACHE INDEX: %d\n",
    index);*/

  memcpy(ethHdr->ether_shost, ifMatch->addr, ETHER_ADDR_LEN);
  memcpy(ethHdr->ether_dhost, arpcache[index].mac, ETHER_ADDR_LEN);

  if(ipHdr->ip_src.s_addr == ipHdr->ip_dst.s_addr){
    ipHdr->ip_dst.s_addr = arpcache[index].ip;
  }

  /*set IP checksum */
  ipHdr->ip_sum = 0;
  ipHdr->ip_sum = calculateChecksum( (void*) ipHdr, sizeof(struct ip));

  
  /* DON'T CHANGE CHECKSUM FOR TCP/UDP PACKETS */
  if(ipHdr->ip_p != TCP_PROTOCOL && ipHdr->ip_p != UDP_PROTOCOL){
    /* set ICMP checksum */
    icmp->checksum = 0;
    icmp->checksum = calculateChecksum( (void*) icmp, 
					_len - (sizeof(struct sr_ethernet_hdr) + sizeof(struct ip)));
  }
  
  sr_send_packet(_sr, _packet, _len,  arpcache[index].interface);/*ifMatch->name);*/
}



/***************************************************************************
 * Return interface matching dIp, NULL if none found
 ***************************************************************************/
struct sr_if *oneOfUs(struct sr_if *US, uint32_t dIp){

  struct sr_if *retVal = US;

  while(retVal != NULL){
    if(retVal->ip == dIp){
      /*fprintf(stderr, "FOUND A MATCHING INTERFACE!!!\n");*/
      return retVal;
    }
    retVal = retVal->next;
  }

  return NULL;
}



/**************************************************
 *
 **************************************************/
void checkRT(struct sr_instance *sr){
  
  struct sr_rt *prev, *RT = sr->routing_table;

  while(RT != NULL && RT->dest.s_addr != 0){
    prev = RT;
    RT = RT->next;
  }
  if (RT == NULL) {
    /*fprintf(stderr, "RT is null. should never happen\n");*/
    exit(1);
  } else if (RT == sr->routing_table)
    return;
  
  prev->next = RT->next;
  RT->next = sr->routing_table;
  sr->routing_table = RT;
}



/****************************************************************************
 * Assumes that the queried IP address is in network byte order
 ***************************************************************************/
struct sr_rt *longestPrefixMatch(uint32_t query, struct sr_rt *sr){
  
  uint32_t i, j, mask, dest, longestMatch = 0, skip;
  struct sr_rt *bestMatch = NULL;
  query = htonl(query);
  while (sr != NULL ) {
    skip = 0;
 
    dest = htonl(sr->dest.s_addr);
    mask = htonl(sr->mask.s_addr);

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
    
    if (skip==0 && j >= longestMatch) {
      longestMatch = j;
      bestMatch = sr;
    }
    sr = sr->next;
  }

  return bestMatch;
}



/****************************************************************************
 * Assumes that the queried IP address is in network byte order
 ***************************************************************************/


/**************************************************
 *
 **************************************************/
void printHello(struct ospfv2_hello_hdr *head){
  
  printf("nmask: ");
  printIp(head->nmask);
  printf("helloint: %i\n", ntohs(head->helloint));
  printf("padding: %i\n", head->padding);
}


/**************************************************
 *
 **************************************************/
uint8_t *getMacForInterface(struct sr_instance *sr, char *interface){
  
  struct sr_if *walker = sr->if_list;
  
  while(walker != NULL){
    if(strcmp(walker->name, interface) == 0){
      return walker->addr;
    }
    walker = walker->next;
  }

  return NULL;
}


