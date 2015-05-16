/*-----------------------------------------------------------------------------
 * file:  sr_pwospf.h
 * date:  Tue Nov 23 23:21:22 PST 2004 
 * Author: Martin Casado
 *
 * Description:
 *
 *---------------------------------------------------------------------------*/

#ifndef SR_PWOSPF_H
#define SR_PWOSPF_H

#include <pthread.h>
#include "includes.h"

/* forward declare */
struct sr_instance;

#define TIME_EXPIRED 0
#define MAX_INTERFACES 4
uint32_t currSeq;


typedef struct dynamic_rt {
  struct in_addr dest;
  struct in_addr gw;
  struct in_addr mask;
  struct in_addr rid;
  char interface[sr_IFACE_NAMELEN];
  uint8_t ttl;
  uint16_t lastSeqNumber;
  uint8_t numHops;
  struct dynamic_rt *next;
} dynrt;

typedef struct dynamic_if {
  struct in_addr ourIp;
  struct in_addr mask;
  uint8_t helloInt;
  struct in_addr neighborRid;
  struct in_addr neighborIp;
  char interface[sr_IFACE_NAMELEN];
  char srcMac[ETHER_ADDR_LEN];
  char dstMac[ETHER_ADDR_LEN];

  struct dynamic_if *next;
} dynif;

struct pwospf_subsys
{
  /* -- pwospf subsystem state variables here -- */
  dynrt *drt; /* dynamic routing table */  
  dynif *dif;
  /* -- thread and single lock for pwospf subsystem -- */
  pthread_t thread;
  pthread_mutex_t lock;
};

int pwospf_init(struct sr_instance* sr);
void pwospf_unlock(struct pwospf_subsys* subsys);
void pwospf_lock(struct pwospf_subsys* subsys);
void printDrt(dynrt *drt);
/**************************************************
 *
 **************************************************/
uint32_t findAttachedInterface(dynif *dIf, uint32_t qIp, char *interface);

dynrt *
dynamicLongestPrefixMatch(uint32_t query, dynrt *drt);

uint32_t
getNextHopsIp(struct sr_instance *sr, char *interface);

#endif /* SR_PWOSPF_H */
