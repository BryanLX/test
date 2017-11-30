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
#include "sr_nat.h"

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
    if (sr->nat != NULL) {
        sr_nat_init(sr->nat);
    }


} /* -- sr_init -- */


struct sr_rt * LPM(struct sr_instance *sr,uint32_t  ip_dst){

      printf("LPM pergormed for ");
      print_addr_ip_int(ip_dst);
      struct sr_rt * result  = 0;
      struct sr_rt * cur = sr->routing_table;
      uint32_t max =0;
      while(cur){
        uint32_t network_id = ntohl(ip_dst) & ntohl(cur->mask.s_addr);
        uint32_t cur_id = ntohl(cur->dest.s_addr) & ntohl(cur->mask.s_addr);
        if(network_id == cur_id){
            if(ntohl(cur->mask.s_addr) > max){
                printf("%u>%u \n",ntohl(cur->mask.s_addr),max);
                result = cur;
                max = ntohl(cur->mask.s_addr);
            }
        }
        cur = cur->next;
      }
      printf("And result is %s",result->interface);
      return result;

}




void handle_packet(struct sr_instance *sr,uint8_t *packet,unsigned int len,struct sr_if *interface,uint32_t ip){
  struct sr_arpentry * result = sr_arpcache_lookup(&sr->cache,ip);
  if (result){
    sr_ethernet_hdr_t * e_header = (sr_ethernet_hdr_t *) packet;

    memcpy(e_header->ether_dhost, result->mac, ETHER_ADDR_LEN);
    memcpy(e_header->ether_shost, interface->addr, ETHER_ADDR_LEN);
    printf("Sending icmp3 \n");
    int re = sr_send_packet(sr, packet,len, interface->name);
    if (re != 0){
      printf("Something wrong when sending packet \n");
    }
    free(result);
  }else{
    struct sr_arpreq * req=sr_arpcache_queuereq(&sr->cache,ip,packet,len,interface->name);
    handle_arpreq(sr,req);
  }

}

void send_icmp(struct sr_instance* sr, int type, int code , uint8_t* packet, unsigned int len){

  printf("Sending ICMP\n");
  /* Get nessary informations*/
  sr_ethernet_hdr_t * e_hdr = (sr_ethernet_hdr_t *) packet;
  sr_ip_hdr_t * ip_hdr = (sr_ip_hdr_t *) (packet + sizeof(struct sr_ethernet_hdr));
  sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

  print_hdr_ip(ip_hdr);
  struct sr_rt *match = LPM(sr,ip_hdr->ip_src);
  printf("Interface is :%s",match->interface);
  if(!match){
    return;
  }
  struct sr_if *out = sr_get_interface(sr, match->interface);

  /*Setting ethernet header*/
  memset(e_hdr->ether_shost, 0, ETHER_ADDR_LEN);
  memset(e_hdr->ether_dhost, 0, ETHER_ADDR_LEN);
  e_hdr->ether_type = htons(ethertype_ip);

  /*Setting ip header*/
  uint32_t temp = ip_hdr->ip_dst;
  ip_hdr->ip_dst = ip_hdr->ip_src;
  ip_hdr->ip_src = temp;



  /*Setting ICMP*/
  icmp_hdr->icmp_type = type;
  icmp_hdr->icmp_code = code;
  icmp_hdr->icmp_sum = 0;
  icmp_hdr->icmp_sum = cksum(icmp_hdr, ntohs(ip_hdr->ip_len) - (ip_hdr->ip_hl * 4));


  /*send the packet*/
  handle_packet(sr,packet,len,out,match->gw.s_addr);

}
void send_icmp_3(struct sr_instance* sr, int type, int code , uint8_t* packet, unsigned int len){

  printf("Sending ICMP_3\n");
  /* Get nessary informations*/
  sr_ip_hdr_t * ip_old = (sr_ip_hdr_t *) (packet + sizeof(struct sr_ethernet_hdr));

  /* Allocate new*/
  uint8_t *icmp = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
  sr_ethernet_hdr_t * e_hdr = (sr_ethernet_hdr_t *) icmp;
  sr_ip_hdr_t * ip_hdr = (sr_ip_hdr_t *) (icmp + sizeof(struct sr_ethernet_hdr));
  sr_icmp_t3_hdr_t *icmp_hdr = (sr_icmp_t3_hdr_t *) (icmp + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

  struct sr_rt *match = LPM(sr,ip_old->ip_src);
  if(!match){
    return;
  }
  struct sr_if *out = sr_get_interface(sr, match->interface);

  /*Setting ethernet header*/
  memset(e_hdr->ether_shost, 0, ETHER_ADDR_LEN);
  memset(e_hdr->ether_dhost, 0, ETHER_ADDR_LEN);
  e_hdr->ether_type = htons(ethertype_ip);

  /*Setting ip header*/
  uint32_t temp = ip_hdr->ip_dst;
  ip_hdr->ip_dst = ip_hdr->ip_src;
  ip_hdr->ip_src = temp;


  ip_hdr->ip_v = ip_old->ip_v;
  ip_hdr->ip_hl = ip_old->ip_hl;
  ip_hdr->ip_tos = 0;
  ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
  ip_hdr->ip_id = htons(0);
  ip_hdr->ip_off = ip_old->ip_off;
  ip_hdr->ip_ttl = 64;
  ip_hdr->ip_p = ip_protocol_icmp;
  ip_hdr->ip_dst = ip_old->ip_src;
  if(code == 3){
    ip_hdr->ip_src = ip_old->ip_dst;
  }else{
    ip_hdr->ip_src = out->ip;
  }
  ip_hdr ->ip_sum = 0;
  ip_hdr ->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));


  /*Setting ICMP*/
  icmp_hdr->icmp_type = type;
  icmp_hdr->icmp_code = code;
  icmp_hdr->icmp_sum = 0;
  icmp_hdr->unused = 0;
  icmp_hdr->next_mtu = 0;
  memcpy(icmp_hdr->data, ip_old, ICMP_DATA_SIZE);
  icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_t3_hdr_t));

  /*send the packet*/
  handle_packet(sr,icmp,sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t),out,match->gw.s_addr);
  free(icmp);
}



void send_arp(struct sr_instance *sr, struct sr_arpreq * req){
    uint8_t* arp = (uint8_t*) malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
    printf("Sending arp broadcast, start processing..... \n");
    sr_arp_hdr_t *arp_header = (sr_arp_hdr_t*) (arp+ sizeof(struct sr_ethernet_hdr));
    sr_ethernet_hdr_t *eth_header = (sr_ethernet_hdr_t*) arp;
    struct sr_if* iface = sr_get_interface(sr, req->packets->iface);

    /* setting eth_header*/
    memset(eth_header->ether_dhost, 255, ETHER_ADDR_LEN);
    memcpy(eth_header->ether_shost, iface->addr, ETHER_ADDR_LEN);
    eth_header->ether_type = htons(ethertype_arp);

    /* setting arp_header*/
    arp_header-> ar_hrd = htons(arp_hrd_ethernet);
    arp_header-> ar_pro = htons(ethertype_ip);
    arp_header-> ar_hln = ETHER_ADDR_LEN;
    arp_header-> ar_pln = 4;
    arp_header-> ar_op = htons(arp_op_request);
    memcpy(arp_header-> ar_sha, iface->addr, ETHER_ADDR_LEN);
    arp_header-> ar_sip = iface->ip;
    memset(arp_header-> ar_tha, 255,ETHER_ADDR_LEN);
    arp_header-> ar_tip = req->ip;

    int size = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
    int result =  sr_send_packet(sr, arp, size,iface->name );
    if (result != 0){
      printf("Something wrong when sending packet \n");
    }
    free(arp);
}



struct sr_if *  get_iface(struct sr_instance *sr, uint32_t ip){
    struct sr_if * temp = sr->if_list;
    while (temp ) {
        if (temp->ip == ip){
          return temp;
        }
        temp = temp->next;
    }
    return NULL;
}

struct sr_if *get_ifaceaddr(struct sr_instance *sr, unsigned char *addr) {
    struct sr_if *cur = 0;

    cur = sr->if_list;

    while (cur) {
        if (memcmp(cur->addr, addr, ETHER_ADDR_LEN) == 0) {
            return cur;
        }
        cur = cur->next;
    }

    return 0;
}

void sr_handlearp(struct sr_instance* sr,uint8_t * packet,unsigned int len,char* interface)
{
    sr_ethernet_hdr_t * ethernet_header = (sr_ethernet_hdr_t *)packet;
    sr_arp_hdr_t* a_header = (sr_arp_hdr_t *) (sizeof(sr_ethernet_hdr_t)+packet);
    unsigned short op = a_header->ar_op;

    if (ntohs(a_header->ar_hrd) != arp_hrd_ethernet)
    {
       return;
    }
    /* check  */
    if (ntohs(a_header->ar_pro) != ethertype_ip)
    {
        return;
    }
    struct sr_if * the_one=get_iface(sr, a_header->ar_tip);
    if(!the_one){
      return;
    }
    if(arp_op_request == ntohs(op) ){
      /* handle arp request*/
      printf("Received arp request, start processing..... \n");
      uint8_t *arp_reply = (uint8_t *)malloc(len);
      struct sr_if *sr_interface = sr_get_interface(sr, interface);
      sr_arp_hdr_t *arp_header = (sr_arp_hdr_t*) (arp_reply + sizeof(struct sr_ethernet_hdr));
      sr_ethernet_hdr_t *eth_header = (sr_ethernet_hdr_t*) arp_reply;
      memcpy(arp_reply,packet,len);

      /* setting eth_header*/
      memcpy(eth_header->ether_dhost, ethernet_header->ether_shost, ETHER_ADDR_LEN);
      memcpy(eth_header->ether_shost, sr_interface->addr, ETHER_ADDR_LEN);
      eth_header->ether_type = htons(ethertype_arp);

      /* setting arp_header*/

      arp_header-> ar_op =  htons(arp_op_reply);
      memcpy(arp_header-> ar_sha, sr_interface->addr, ETHER_ADDR_LEN);
      arp_header-> ar_sip = sr_interface->ip;
      memcpy(arp_header-> ar_tha, a_header->ar_sha,ETHER_ADDR_LEN);
      arp_header-> ar_tip = a_header->ar_sip;

      printf("Sending replay: \n");
      handle_packet(sr,arp_reply,len,sr_interface,a_header->ar_sip);
      free(arp_reply);
    }else if (arp_op_reply == ntohs(op) ){
      /* handle arp reply*/
        printf("Received arp reply, start processing..... \n");

        struct sr_arpreq *request = sr_arpcache_insert(&sr->cache,a_header->ar_sha, a_header->ar_sip);
        if(request){
          struct sr_packet *p_node = request->packets;
          /* forwarding all packet are waiting */
          while(p_node){
            struct sr_if *inface = sr_get_interface(sr, p_node->iface);

            if(inface){
              ethernet_header= (sr_ethernet_hdr_t *)p_node->buf;
    					memcpy(ethernet_header->ether_dhost, a_header->ar_sha, ETHER_ADDR_LEN);
              memcpy(ethernet_header->ether_shost, inface->addr, ETHER_ADDR_LEN);
              int result = sr_send_packet(sr, p_node->buf, p_node->len, p_node->iface);
    					if (result !=0){
                  printf("Waiting packet sending failed \n");
              }

            }

  					p_node = p_node->next;
          }
          sr_arpreq_destroy(&sr->cache, request);
        }
    }else{
        printf("Unkown arp opcode \n");
    }
}


void sr_handleip(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{

      /* Get necessary informaiton*/
      struct sr_if *iface = sr_get_interface(sr, interface);
      /*sr_ethernet_hdr_t *e_header = (sr_ethernet_hdr_t*) packet;*/
      sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
      struct sr_if * the_one=get_iface(sr, ip_header->ip_dst);
      /*struct sr_if *sr_interface = sr_get_interface(sr, interface);*/
      /* Check if it is send to me*/


      if (ip_header->ip_ttl <= 1 ){
          if(ip_header->ip_ttl == 1 &&  the_one){

          }else{
          printf("Received ip with TTL less or equal to to  1, packet been dropped \n");

          send_icmp_3(sr, 11, 0, packet,len);
          return;
        }
      }

      printf("ip_dis:%d \n  ,ifaceip: %d \n",ip_header->ip_dst,iface->ip);
      if (the_one){

          printf("Received ip for me, start processing..... \n");
          if (ip_header->ip_p == ip_protocol_icmp){
            sr_icmp_hdr_t* icmp_header = (sr_icmp_hdr_t* )(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
            print_hdr_icmp(icmp_header);
            printf("ICMP type is %s\n",icmp_header->icmp_type);
            if (sr->nat_enable ==1 ){
              printf("111111111111");
              handle_nat(sr,packet,len,interface);
              send_icmp(sr, 0, 0, packet,len);
              return;
            }
            if(icmp_header->icmp_type == 8){
              printf("Received icmp echo , start processing..... \n");
              send_icmp(sr, 0, 0, packet,len);
              return;
            }
          } else if(ip_header->ip_p==6||ip_header->ip_p==17){
            printf("Sending port unreachable\n");
            send_icmp_3(sr, 3, 3, packet,len);
            return;
          }else{
            printf("Do nothing\n");
          }
      }else{

          printf("Received ip not for me, start processing..... \n");
          /*check rtable, perform longest prefix match*/
          if (sr->nat_enable ==1 ){
            handle_nat(sr,packet,len,interface);
          }
          ip_header->ip_ttl--;

          if(ip_header->ip_ttl <1){
            send_icmp_3(sr,11, 0, packet,len);
            return;
          }
          ip_header->ip_sum = 0;
          ip_header->ip_sum = cksum(ip_header, sizeof(struct sr_ip_hdr));
          struct sr_rt* result = LPM(sr,ip_header->ip_dst);

          if(result){
            printf("LPM found %s\n",sr_get_interface(sr, result->interface)->name);
            handle_packet(sr,packet,len,sr_get_interface(sr, result->interface),result->gw.s_addr);

          }else{
            printf("LPM not found \n");

            send_icmp_3(sr, 3, 0, packet,len);
          }
      }

}

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

    /* fill in code here */
    print_hdrs(packet,len);
    if (len < sizeof(sr_ethernet_hdr_t)){
        return;
    }
    /*First decide which type it is*/
    uint16_t type = ethertype(packet);
    printf("Type is : %d\n", type);
    if (type == ethertype_arp){
      printf("ARP handleing.......\n");
      sr_handlearp(sr,packet,len,interface);
    }else if (type == ethertype_ip){
      printf("IP handleing.......\n");
      sr_handleip(sr,packet,len,interface);
    }else{
      printf("Type is unkown.");
    }
}/* end sr_ForwardPacket */
