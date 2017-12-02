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
#include <assert.h>
#include <stdlib.h>
#include <string.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_send_arpreply(struct sr_instance *sr, uint8_t *orig_pkt,
 *             unsigned int orig_len, struct sr_if *src_iface)
 * Scope:  Local
 *
 * Send an ARP reply packet in response to an ARP request for one of
 * the router's interfaces 
 *---------------------------------------------------------------------*/
void sr_send_arpreply(struct sr_instance *sr, uint8_t *orig_pkt,
    unsigned int orig_len, struct sr_if *src_iface)
{
  /* Allocate space for packet */
  unsigned int reply_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
  uint8_t *reply_pkt = (uint8_t *)malloc(reply_len);
  if (NULL == reply_pkt)
  {
    fprintf(stderr,"Failed to allocate space for ARP reply");
    return;
  }

  sr_ethernet_hdr_t *orig_ethhdr = (sr_ethernet_hdr_t *)orig_pkt;
  sr_arp_hdr_t *orig_arphdr = 
      (sr_arp_hdr_t *)(orig_pkt + sizeof(sr_ethernet_hdr_t));

  sr_ethernet_hdr_t *reply_ethhdr = (sr_ethernet_hdr_t *)reply_pkt;
  sr_arp_hdr_t *reply_arphdr = 
      (sr_arp_hdr_t *)(reply_pkt + sizeof(sr_ethernet_hdr_t));

  /* Populate Ethernet header */
  memcpy(reply_ethhdr->ether_dhost, orig_ethhdr->ether_shost, ETHER_ADDR_LEN);
  memcpy(reply_ethhdr->ether_shost, src_iface->addr, ETHER_ADDR_LEN);
  reply_ethhdr->ether_type = orig_ethhdr->ether_type;

  /* Populate ARP header */
  memcpy(reply_arphdr, orig_arphdr, sizeof(sr_arp_hdr_t));
  reply_arphdr->ar_hrd = orig_arphdr->ar_hrd;
  reply_arphdr->ar_pro = orig_arphdr->ar_pro;
  reply_arphdr->ar_hln = orig_arphdr->ar_hln;
  reply_arphdr->ar_pln = orig_arphdr->ar_pln;
  reply_arphdr->ar_op = htons(arp_op_reply); 
  memcpy(reply_arphdr->ar_tha, orig_arphdr->ar_sha, ETHER_ADDR_LEN);
  reply_arphdr->ar_tip = orig_arphdr->ar_sip;
  memcpy(reply_arphdr->ar_sha, src_iface->addr, ETHER_ADDR_LEN);
  reply_arphdr->ar_sip = src_iface->ip;

  /* Send ARP reply */
  printf("Send ARP reply\n");
  print_hdrs(reply_pkt, reply_len);
  sr_send_packet(sr, reply_pkt, reply_len, src_iface->name);
  free(reply_pkt);
} /* -- sr_send_arpreply -- */

/*---------------------------------------------------------------------
 * Method: sr_send_arprequest(struct sr_instance *sr, 
 *             struct sr_arpreq *req,i struct sr_if *out_iface)
 * Scope:  Local
 *
 * Send an ARP reply packet in response to an ARP request for one of
 * the router's interfaces 
 *---------------------------------------------------------------------*/
void sr_send_arprequest(struct sr_instance *sr, struct sr_arpreq *req,
    struct sr_if *out_iface)
{
  /* Allocate space for ARP request packet */
  unsigned int reqst_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
  uint8_t *reqst_pkt = (uint8_t *)malloc(reqst_len);
  if (NULL == reqst_pkt)
  {
    fprintf(stderr,"Failed to allocate space for ARP reply");
    return;
  }

  sr_ethernet_hdr_t *reqst_ethhdr = (sr_ethernet_hdr_t *)reqst_pkt;
  sr_arp_hdr_t *reqst_arphdr = 
      (sr_arp_hdr_t *)(reqst_pkt + sizeof(sr_ethernet_hdr_t));

  /* Populate Ethernet header */
  memset(reqst_ethhdr->ether_dhost, 0xFF, ETHER_ADDR_LEN);
  memcpy(reqst_ethhdr->ether_shost, out_iface->addr, ETHER_ADDR_LEN);
  reqst_ethhdr->ether_type = htons(ethertype_arp);

  /* Populate ARP header */
  reqst_arphdr->ar_hrd = htons(arp_hrd_ethernet);
  reqst_arphdr->ar_pro = htons(ethertype_ip);
  reqst_arphdr->ar_hln = ETHER_ADDR_LEN;
  reqst_arphdr->ar_pln = sizeof(uint32_t);
  reqst_arphdr->ar_op = htons(arp_op_request); 
  memcpy(reqst_arphdr->ar_sha, out_iface->addr, ETHER_ADDR_LEN);
  reqst_arphdr->ar_sip = out_iface->ip;
  memset(reqst_arphdr->ar_tha, 0x00, ETHER_ADDR_LEN);
  reqst_arphdr->ar_tip = req->ip;

  /* Send ARP request */
  printf("Send ARP request\n");
  print_hdrs(reqst_pkt, reqst_len);
  sr_send_packet(sr, reqst_pkt, reqst_len, out_iface->name);
  free(reqst_pkt);
} /* -- sr_send_arprequest -- */

/*---------------------------------------------------------------------
 * Method: sr_handle_arpreq(struct sr_instance *sr, 
 *             struct sr_arpreq *req, struct sr_if *out_iface)
 * Scope:  Global
 *
 * Perform processing for a pending ARP request: do nothing, timeout, or  
 * or generate an ARP request packet 
 *---------------------------------------------------------------------*/
void sr_handle_arpreq(struct sr_instance *sr, struct sr_arpreq *req,
    struct sr_if *out_iface)
{
  time_t now = time(NULL);
  if (difftime(now, req->sent) >= 1.0)
  {
    if (req->times_sent >= 5)
    {
      /*********************************************************************/
      /* TODO: send ICMP host uncreachable to the source address of all    */
      /* packets waiting on this request                                   */
      struct sr_packet *curr_packet = req->packets;
      while(curr_packet != NULL){
         send_icmp_message(sr, curr_packet, 3, 0);
         curr_packet = curr_packet->next;
      }

	  
      /*sr_send_packet (sr_vns_comm) - Send packet*/


      /*********************************************************************/

      sr_arpreq_destroy(&(sr->cache), req);
    }
    else
    { 
      /* Send ARP request packet */
      sr_send_arprequest(sr, req, out_iface);
       
      /* Update ARP request entry to indicate ARP request packet was sent */ 
      req->sent = now;
      req->times_sent++;
    }
  }
} /* -- sr_handle_arpreq -- */

/*---------------------------------------------------------------------
 * Method: void sr_waitforarp(struct sr_instance *sr, uint8_t *pkt,
 *             unsigned int len, uint32_t next_hop_ip, 
 *             struct sr_if *out_iface)
 * Scope:  Local
 *
 * Queue a packet to wait for an entry to be added to the ARP cache
 *---------------------------------------------------------------------*/
void sr_waitforarp(struct sr_instance *sr, uint8_t *pkt,
    unsigned int len, uint32_t next_hop_ip, struct sr_if *out_iface)
{
    struct sr_arpreq *req = sr_arpcache_queuereq(&(sr->cache), next_hop_ip, 
            pkt, len, out_iface->name);
    sr_handle_arpreq(sr, req, out_iface);
} /* -- sr_waitforarp -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket_arp(struct sr_instance *sr, uint8_t *pkt,
 *             unsigned int len, struct sr_if *src_iface)
 * Scope:  Local
 *
 * Handle an ARP packet that was received by the router
 *---------------------------------------------------------------------*/
void sr_handlepacket_arp(struct sr_instance *sr, uint8_t *pkt,
    unsigned int len, struct sr_if *src_iface)
{
  /* Drop packet if it is less than the size of Ethernet and ARP headers */
  if (len < (sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)))
  {
    printf("Packet is too short => drop packet\n");
    return;
  }

  sr_arp_hdr_t *arphdr = (sr_arp_hdr_t *)(pkt + sizeof(sr_ethernet_hdr_t));

  switch (ntohs(arphdr->ar_op))
  {
  case arp_op_request:
  {
    /* Check if request is for one of my interfaces */
    if (arphdr->ar_tip == src_iface->ip)
    { sr_send_arpreply(sr, pkt, len, src_iface); }
    break;
  }
  case arp_op_reply:
  {
    /* Check if reply is for one of my interfaces */
    if (arphdr->ar_tip != src_iface->ip)
    { break; }
    
    /* Update ARP cache with contents of ARP reply */
    struct sr_arpreq *req = sr_arpcache_insert(&(sr->cache), arphdr->ar_sha, 
        arphdr->ar_sip);
    /* Process pending ARP request entry, if there is one */
    if (req != NULL)
    {
      /*********************************************************************/
      /* TODO: send all packets on the req->packets linked list            */
      
      struct sr_packet *packet = req->packets;	  
      while(packet != NULL)
      {
	    /*There should now be an arp entry*/
	    sr_ethernet_hdr_t* e_hdr = (sr_ethernet_hdr_t *) (packet->buf);
	    sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t *) (packet->buf + sizeof(sr_ethernet_hdr_t));
	    struct sr_arpentry* arp_entry = sr_arpcache_lookup(&(sr->cache), ip_hdr->ip_dst);
	    if(arp_entry != NULL)
	    {
		/*Update ethernet headers*/
		memcpy(e_hdr->ether_shost, (sr_get_interface(sr, packet->iface)->addr), ETHER_ADDR_LEN);
		memcpy(e_hdr->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
	    	sr_send_packet(sr, packet->buf, packet->len, packet->iface);
	    }
	    packet = packet->next;
	    req->packets = packet;
      }
	  
	  
	  
	  
      /*sr_send_packet (sr_vns_comm) - Send packet*/

      /*********************************************************************/

      /* Release ARP request entry */
      sr_arpreq_destroy(&(sr->cache), req);
    }
    break;
  }    
  default:
    printf("Unknown ARP opcode => drop packet\n");
    return;
  }
} /* -- sr_handlepacket_arp -- */

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

  printf("*** -> Received packet of length %d \n",len);

  
  /*************************************************************************/
  /* TODO: Handle packets                                                  */
  
  
  /* Extract the ethernet header and ethernet type from the packet */
  sr_ethernet_hdr_t *etherhdr = (sr_ethernet_hdr_t *)(packet);
  uint16_t ethtype = ethertype(packet);
  
/*check to see if packet is a broadcast ARP packet*/
/*then check to see if packet was meant for the router*/
/*then check to see if packet needs to be forwarded*/

  if(is_broadcast_packet(etherhdr)){
     if(ethtype == ethertype_arp){
        printf("This is a BROADCAST ARP Packet!\n");
        print_hdrs(packet, len);
        sr_handlepacket_arp(sr, packet, len, sr_get_interface(sr, interface));
        /*print_addr_ip_int(htonl(ip));*/
     }
     else{
        fprintf(stderr, "ERROR: Broadcast packet doesn't have an ARP header");
        print_hdrs(packet, len);
     }
  }
  else if(is_packet_addressed_to_router(sr, packet, interface)){
     printf("This packet is addressed to the router!\n"); 
     print_hdrs(packet, len);
     /*check that it's an ip packet*/
     if(ethtype == ethertype_ip){
        sr_ip_hdr_t *destination = (sr_ip_hdr_t *)(packet + (sizeof(sr_ethernet_hdr_t)));
	/*check that it's an icmp packet*/
        if(is_icmp(destination->ip_p)){
            const int ICMP_ECHO_REQUEST = 8;

	    /*make icmp packet and set values*/
            sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));   
            if(icmp_hdr->icmp_type == ICMP_ECHO_REQUEST){
               printf("Router received ping!!!\n");
               struct sr_packet *curr_packet = (struct sr_packet *)malloc(sizeof(struct sr_packet));
               curr_packet->buf = packet;
               curr_packet->len = len;
               curr_packet->iface = interface;
               send_echo_reply(sr, curr_packet);
               free(curr_packet);
               
            }
        }
        else if(destination->ip_p == 6 || destination->ip_p == 17){
           printf("Sending port unreachable icmp message!\n");
           struct sr_packet *curr_packet = (struct sr_packet *)malloc(sizeof(struct sr_packet));
           curr_packet->buf = packet;
           curr_packet->len = len;
           curr_packet->iface = interface;
           send_icmp_message(sr, curr_packet, 3, 3);
           free(curr_packet);
        }
     }
     else{
        fprintf(stderr, "ERROR: Received a packet address to the router that is NOT IP");
     }
  }

    else{
     printf("This packet is NOT addressed to the router\n"); 
     print_hdrs(packet, len);
     /*forward the packet to the correct host*/
     if(ethtype == ethertype_ip){
        sr_ip_hdr_t *destination = (sr_ip_hdr_t *)(packet + (sizeof(sr_ethernet_hdr_t)));
        int min_length = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t);
        if(len < min_length){
           fprintf(stderr, "This IP packet is not long enough!\n");
           return;
        }
        /*check the checksum on this packet*/
        int ip_header_length = sizeof(sr_ip_hdr_t);
        uint16_t check_sum = cksum(destination, ip_header_length); 
        if(check_sum != 0xffff){
           fprintf(stderr, "Incorrect checksum. Dropping packet...\n");
           return;
        }

        destination->ip_ttl--;
        if(destination->ip_ttl == 0){
           struct sr_packet *curr_packet = (struct sr_packet *)malloc(sizeof(struct sr_packet));
           curr_packet->buf = packet;
           curr_packet->len = len;
           curr_packet->iface = interface;
           send_icmp_message(sr, curr_packet, 11, 0);
           return;
        }
        /*recompute the checksum for this packet*/
        destination->ip_sum = 0x0000;
        destination->ip_sum = cksum(destination, ip_header_length);

        uint32_t ip_dest = htonl(destination->ip_dst);
        char *iface_to_send = get_longest_prefix_match(sr, ip_dest);
        if(iface_to_send == NULL){
           struct sr_packet *curr_packet = (struct sr_packet *)malloc(sizeof(struct sr_packet));
           curr_packet->buf = packet;
           curr_packet->len = len;
           curr_packet->iface = interface;
           send_icmp_message(sr, curr_packet, 3, 0); 
           return;
        }
        printf("Interface to send: %s\n", iface_to_send);
        struct sr_arpentry *arp_entry = sr_arpcache_lookup(&(sr->cache), destination->ip_dst);
        if(arp_entry != NULL){
           printf("IP -> ARP CACHE HIT\n");
	   printf("ARP ENTRY valid: %d\n", arp_entry->valid);
	   uint32_t rentry_ip = arp_entry->ip;
	   printf("Router entry IP: \n"); 
	   print_addr_ip_int(htonl(rentry_ip));
	   memcpy(etherhdr->ether_shost, (sr_get_interface(sr, iface_to_send)->addr), ETHER_ADDR_LEN);
	   memcpy(etherhdr->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN); 
	   print_hdrs(packet, len);
	   sr_send_packet(sr, packet, len, iface_to_send);
	   free(arp_entry);
        }
        else{
           printf("IP -> ARP CACHE MISS\n");
	   /*print cache*/
	   /*sr_arpcache_dump(&(sr->cache));*/
           printf("Interface: %s\n", iface_to_send);
           sr_waitforarp(sr, packet, len, ntohl(ip_dest), sr_get_interface(sr, iface_to_send));
        }
     }
     else if(ethtype == ethertype_arp){
        sr_handlepacket_arp(sr, packet, len, sr_get_interface(sr, interface));
     }
     else{
        fprintf(stderr, "ERROR: We received a packet destined for another host but it did not have an IP or ARP header");
     }
  }
 
  /* used cksum method from the sr_utils.c module for all checksum calculations. 
Decremented ttl for the else clause when a packet is not addressed to the router. 
*/
  /*Check the packet to see if its even long enough*/
/*
  if (len < (sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) ))
  {
    printf("Packet is too short => drop packet\n"); 
    return;
  }
*/

  /*	extract the ip header (iphdr) from the packet.
   *	based on code from sr_handlepacket_arp where the arp header is extracted	*/
 
/*sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  
  printf("Gonna run checksum on IP headers...\n"); 
  uint16_t chksum = ~checksum(iphdr);  

  if (chksum != 0){ 
	printf("IP Checksum error => drop packet\n");
    return;
  }
  */
  
  /*Decrement the TTL by one*/

/*if ((iphdr->ip_ttl) > 1){ 
    (iphdr->ip_ttl) -= 1;
  }else{
	printf("TTL expire on pkt\n"); 
    return;
  }
  unsigned char *bytes = (unsigned char*) iphdr;

*/
  /*
  bytes[10] = 0;
  bytes[11] = 0;
  chksum = ~checksum(iphdr);
  bytes[10] = (chksum & 0xFF00) >> 8;
  bytes[11] = chksum & 0x00FF;
  
*/

  /*Find the entry in the routing table that has the longest matching prefix IP*/
  
  /*Check ARP cache for next-hop MAC address that goes to the next-hop IP*/
  /*  if its there, send the packet*/
  /*  if its NOT there, send an ARP request for the next-hop IP*/
  /*    add packets to queue of packets waiting on this ARP*/
  
  
  /*sr_send_packet (sr_vns_comm) - Send packet*/
  /*sr_arpreq *sr_arpcache_queuereq (sr_arpcache) - Add to the arp request queue*/


  /*************************************************************************/

}/* end sr_ForwardPacket */




/* Calculate checksum all the elements (as 16bit ints) in an IP header*/
uint16_t checksum( sr_ip_hdr_t *iphdr ){
  uint32_t chksum = 0; 	/* Begin the checksum count at 0.*/
					/* Use uint32 instead of short16 for ease of overflow addition*/

  
  printf("Beginning checksum computation\n\n");
  
  int i = 0;
  printf("Ip header has %d bytes\n", (int)sizeof(sr_ip_hdr_t));
  for (; i < sizeof(sr_ip_hdr_t) / 2; i++){
        /* For every pair of bytes (16bit)*/
	/* Add each pair of bytes as if they were a 16bit int*/
	uint16_t byte1 = *((unsigned char*) iphdr + 2*i);
	uint16_t byte2 = *((unsigned char*) iphdr + 2*i+1);
	printf("Byte %d - %02x \n", (2*i), byte1);
	printf("Byte %d - %02x \n", (2*i+1), byte2);
	chksum += (byte1 << 8) + byte2;
	printf("Current checksum - %08x \n", chksum);
	/*				  upper byte                                       +       lower byte    */
	}

  /*	   lower part of sum + accumulated overflow >> 16*/
  chksum = (chksum & 0xFFFF) + ((chksum >> 16) & 0xFFFF); 	/*add the overflow back*/
  printf("Checksum after 1 overflow check - %08x \n", chksum);
  chksum = (chksum & 0xFFFF) + ((chksum >> 16) & 0xFFFF); 	/*shouldn't do anything, added in case of double overflow*/
  printf("Checksum after 2 overflow checks - %08x \n", chksum);
  uint16_t out = chksum;
  return out;
}

int is_broadcast_packet(struct sr_ethernet_hdr *ethernet_hdr){
  int i;
  for(i = 0; i < ETHER_ADDR_LEN; i++){
      /*if any byte in the destination host is not 0xFF, then the packet is not a broadcast packet*/
      if(ethernet_hdr->ether_dhost[i] != 0xFF){
         return 0;
      }
  }
  return 1;
}

int is_packet_addressed_to_router(struct sr_instance *sr, uint8_t *packet, char *interface){
  sr_ip_hdr_t *destination = (sr_ip_hdr_t *)(packet + (sizeof(sr_ethernet_hdr_t)));
  struct sr_if *curr_entry = sr->if_list;
  while(curr_entry != NULL){
     if(curr_entry->ip == destination->ip_dst){
        return 1;
     }
     curr_entry = curr_entry->next;
  }
  return 0;
}


int is_icmp(uint8_t ip_protocol){
  if(ip_protocol == ip_protocol_icmp){
     return 1;
  }
  return 0;
}
char *get_longest_prefix_match(struct sr_instance *sr, uint32_t ip_dest){
  char *iface_to_send;
  int max_matching_bits = 0;
  /*int CHAR_BIT = 8;*/
  struct sr_rt *curr_entry = sr->routing_table; 
  printf("IP to compare: \n");
  print_addr_ip_int(ip_dest);
  while(curr_entry != NULL){
     uint32_t curr_ip = htonl(*(uint32_t *)&curr_entry->dest); 
     printf("Curr IP: \n");
     print_addr_ip_int(curr_ip);
     int matching_bits = 0;
     int i;
     /*printf("starting at: %lu\n", sizeof(ip_dest) * (CHAR_BIT-1));*/
     for(i = 31; i >= 0; --i){
        int ip_dest_bit = (ip_dest >> i) & 1;
        int curr_entry_bit = (curr_ip >> i) & 1;
        if(ip_dest_bit == curr_entry_bit){
           matching_bits++;
        }
        else{
           break;
        }
     }
     printf("matching bits: %d\n", matching_bits);
     if(matching_bits > max_matching_bits){
        max_matching_bits = matching_bits;
        iface_to_send = curr_entry->interface;
     }
     curr_entry = curr_entry->next;
  }

  if(max_matching_bits != 32){
     return NULL;
  }

  return iface_to_send;
}


void send_icmp_message(struct sr_instance *sr, struct sr_packet *curr_packet, uint8_t type, uint8_t code){
   printf("SEND ICMP host unreachable!!\n");
   printf("sizeof(sr_icmp_t3_hdr_t): %lu\n", sizeof(sr_icmp_t3_hdr_t));
   printf("sizeof(sr_icmp_hdr_t): %lu\n", sizeof(sr_icmp_hdr_t));
   int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t) + 8;
   uint8_t *packet = (uint8_t *)malloc(len); 
   sr_ethernet_hdr_t *ether_hdr = (sr_ethernet_hdr_t *)packet;
   sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
   sr_icmp_t3_hdr_t *icmp_hdr = (sr_icmp_t3_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

   uint8_t *queued_packet = curr_packet->buf;
   sr_ip_hdr_t *q_hdr = (sr_ip_hdr_t *)(queued_packet + sizeof(sr_ethernet_hdr_t));

   /*create icmp header*/
   icmp_hdr->icmp_type = type; 
   icmp_hdr->icmp_code = code;
   icmp_hdr->icmp_sum = 0x0000;
   memcpy(icmp_hdr->data, q_hdr, sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t) + 8);
   icmp_hdr->icmp_sum = cksum((uint16_t *)icmp_hdr, sizeof(sr_icmp_t3_hdr_t)); 

   /*create ip header*/
   ip_hdr->ip_hl = 5; /* 5 words*/
   ip_hdr->ip_v = 4;  /* IPv4*/ 
   ip_hdr->ip_tos = 0;
   ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
   ip_hdr->ip_id = 0;
   ip_hdr->ip_off = 0;
   ip_hdr->ip_ttl = 64; /*arbitrarily assigned value*/
   ip_hdr->ip_p = ip_protocol_icmp;
   ip_hdr->ip_sum = 0x0000;
   ip_hdr->ip_dst = q_hdr->ip_src;
   char *iface_to_send = get_longest_prefix_match(sr, htonl(ip_hdr->ip_dst));
   ip_hdr->ip_src = sr_get_interface(sr, iface_to_send)->ip;
   ip_hdr->ip_sum = cksum((uint8_t *)ip_hdr, sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));

   /*create ethernet header*/
   sr_ethernet_hdr_t *q_eth_hdr = (sr_ethernet_hdr_t *)(queued_packet);
   memcpy(ether_hdr->ether_dhost, q_eth_hdr->ether_shost, sizeof(uint8_t) * ETHER_ADDR_LEN);
   memcpy(ether_hdr->ether_shost, sr_get_interface(sr, iface_to_send)->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);
   ether_hdr->ether_type = htons(ethertype_ip);

   printf("CANNOT REACH HOST\n");

   printf("Sending packet over interface: %s of size: %d\n", iface_to_send, len);
   print_hdrs(packet, len);
   sr_send_packet(sr, packet, len, iface_to_send);

   free(packet);
}


void send_echo_reply(struct sr_instance *sr, struct sr_packet *curr_packet){
   int len = 60 + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t);
   uint8_t *packet = (uint8_t *)malloc(len); 
   sr_ethernet_hdr_t *ether_hdr = (sr_ethernet_hdr_t *)packet;
   sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
   sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

   uint8_t *queued_packet = curr_packet->buf;
   sr_ip_hdr_t *q_hdr = (sr_ip_hdr_t *)(queued_packet + sizeof(sr_ethernet_hdr_t));
   sr_icmp_hdr_t *q_icmp = (sr_icmp_hdr_t *)(queued_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

   /*create icmp header*/
   memcpy(icmp_hdr, q_icmp, sizeof(sr_icmp_hdr_t) + 60);
   icmp_hdr->icmp_type = 0; 
   icmp_hdr->icmp_code = 0;
   icmp_hdr->icmp_sum = 0x0000;
   icmp_hdr->icmp_sum = cksum((uint16_t *)icmp_hdr, sizeof(sr_icmp_hdr_t) + 60);

   /*create ip header*/
   ip_hdr->ip_hl = 5; /* 5 words*/
   ip_hdr->ip_v = 4;  /* IPv4*/ 
   ip_hdr->ip_tos = 0;
   ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t) + 60);
   ip_hdr->ip_id = 0;
   ip_hdr->ip_off = 0;
   ip_hdr->ip_ttl = 64; /*arbitrarily assigned value*/
   ip_hdr->ip_p = ip_protocol_icmp;
   ip_hdr->ip_sum = 0x0000;
   ip_hdr->ip_dst = q_hdr->ip_src;
   char *iface_to_send = get_longest_prefix_match(sr, htonl(ip_hdr->ip_dst));
   ip_hdr->ip_src = sr_get_interface(sr, iface_to_send)->ip;
   ip_hdr->ip_sum = cksum((uint8_t *)ip_hdr, sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t) + 60);

   /*create ethernet header*/
   sr_ethernet_hdr_t *q_eth_hdr = (sr_ethernet_hdr_t *)(queued_packet);
   memcpy(ether_hdr->ether_dhost, q_eth_hdr->ether_shost, sizeof(uint8_t) * ETHER_ADDR_LEN);
   memcpy(ether_hdr->ether_shost, sr_get_interface(sr, iface_to_send)->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);
   ether_hdr->ether_type = htons(ethertype_ip);

   printf("SENDING ECHO REPLY\n");

   printf("Sending packet over interface: %s of size: %d\n", iface_to_send, len);
   print_hdrs(packet, len);
   sr_send_packet(sr, packet, len, iface_to_send);

   free(packet);
}


