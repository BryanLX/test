
#include <signal.h>
#include <assert.h>
#include "sr_nat.h"
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

int sr_nat_init(struct sr_nat *nat) { /* Initializes the nat */

  assert(nat);

  /* Acquire mutex lock */
  pthread_mutexattr_init(&(nat->attr));
  pthread_mutexattr_settype(&(nat->attr), PTHREAD_MUTEX_RECURSIVE);
  int success = pthread_mutex_init(&(nat->lock), &(nat->attr));

  /* Initialize timeout thread */

  pthread_attr_init(&(nat->thread_attr));
  pthread_attr_setdetachstate(&(nat->thread_attr), PTHREAD_CREATE_JOINABLE);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_create(&(nat->thread), &(nat->thread_attr), sr_nat_timeout, nat);

  /* CAREFUL MODIFYING CODE ABOVE THIS LINE! */


  /* Initialize any variables here */
  nat->mappings = NULL;
  nat->icmp_query_timeout = 60;
  nat->tcp_established_timeout = 7440;
  nat->tcp_transitory_timeout = 300;
  nat->counter = START_PORT;


  return success;
}


int sr_nat_destroy(struct sr_nat *nat) {  /* Destroys the nat (free memory) */

  pthread_mutex_lock(&(nat->lock));

  /* free nat memory here */

  /* free mapping*/
  struct sr_nat_mapping *mapping = nat->mappings;
  struct sr_nat_mapping *prev =  NULL;
  struct sr_nat_connection * con = NULL;
  struct sr_nat_connection * con_prev = NULL;
  while(mapping){
    prev = mapping;
    con = mapping->conns;
    while(con){
      con_prev = con;
      con = con->next;
      free(con_prev);
    }
    mapping = mapping->next;
    free(prev);
  }

  pthread_kill(nat->thread, SIGKILL);
  return pthread_mutex_destroy(&(nat->lock)) &&
    pthread_mutexattr_destroy(&(nat->attr));

}

void *sr_nat_timeout(void *nat_ptr) {  /* Periodic Timout handling */
  struct sr_nat *nat = (struct sr_nat *)nat_ptr;
  while (1) {
    sleep(1.0);
    pthread_mutex_lock(&(nat->lock));



    /* handle periodic tasks here */

    pthread_mutex_unlock(&(nat->lock));
  }
  return NULL;
}

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy */
  struct sr_nat_mapping *copy = NULL;

  struct sr_nat_mapping *cur = nat->mappings;

  while (cur) {
       if (cur->type == type && cur->aux_ext == aux_ext) {
           copy = (struct sr_nat_mapping *) malloc(sizeof(struct sr_nat_mapping));
           memcpy(copy, cur, sizeof(struct sr_nat_mapping));
           break;

       }
       cur = cur->next;
   }
  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy. */
  struct sr_nat_mapping *copy = NULL;
  struct sr_nat_mapping *cur = nat->mappings;

  while (cur) {
       if (cur->type == type && cur->ip_int == ip_int && cur->aux_int == aux_int) {
           copy = (struct sr_nat_mapping *) malloc(sizeof(struct sr_nat_mapping));
           memcpy(copy, cur, sizeof(struct sr_nat_mapping));
           break;

       }
       cur = cur->next;
   }
  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Insert a new mapping into the nat's mapping table.
   Actually returns a copy to the new mapping, for thread safety.
 */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle insert here, create a mapping, and then return a copy of it */

  struct sr_nat_mapping *mapping = sr_nat_lookup_internal(nat, ip_int, aux_int, type);
  if (mapping) {
        return mapping;
  }
  mapping = malloc(sizeof(struct sr_nat_mapping));

  mapping->ip_int = ip_int;
  mapping->aux_int = aux_int;
  mapping->ip_ext = 0;
  mapping->aux_ext = nat->counter;
  nat->counter = (nat->counter+1)%END_PORT;
  mapping->last_updated = time(NULL);
  mapping->conns = NULL;
  mapping->type = type;
  mapping->next = nat->mappings;
  nat->mappings = mapping;

  pthread_mutex_unlock(&(nat->lock));
  return mapping;
}

struct sr_nat_connection* sr_nat_lookup_connection(struct sr_nat* nat,struct sr_nat_mapping *mapping, uint32_t ip){

    pthread_mutex_lock(&(nat->lock));

    assert(mapping);
    struct sr_nat_connection* result =NULL;
    struct sr_nat_connection* cur = mapping->conns;
    while(cur){
        if(ip == cur->ip){
            result = (struct sr_nat_connection *) malloc(sizeof(struct sr_nat_connection));
            memcpy(result, cur, sizeof(struct sr_nat_connection));
        }
        cur = cur->next;
    }

    pthread_mutex_unlock(&(nat->lock));

    return result;
}



void handle_nat(struct sr_instance* sr,uint8_t * packet,unsigned int len,char* interface) {
    struct sr_nat * nat = sr->nat;
    pthread_mutex_lock(&(sr->nat.lock));
    /* get current information */
    sr_ethernet_hdr_t *e_hdr = (sr_ethernet_hdr_t *) packet;
    sr_ip_hdr_t *ip_hdr = (struct sr_ip_hdr *)(packet + sizeof(sr_ethernet_hdr_t));
    sr_icmp_t3_hdr_t *icmp_hdr  = (sr_icmp_t3_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    /* sr_tcp_hdr_t *tcp_hdr  = (sr_tcp_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)); */
    uint8_t protocol = ip_hdr->ip_p;
    struct sr_nat_mapping *result = NULL;
    if(protocol == ip_protocol_icmp){
      printf("Nat with ICMP\n");
      sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
      if(strncmp(interface, NAT_IN, sr_IFACE_NAMELEN)==0) {
          /* inside to outside */
          printf("insideo to outside  \n");
          result = sr_nat_lookup_internal(nat, ip_hdr->ip_src, icmp_hdr->icmp_id, nat_mapping_icmp);
          if (!result){
              /* If not exist then Insert */
              result = sr_nat_insert_mapping(nat, ip_hdr->ip_src, icmp_hdr->icmp_id, nat_mapping_icmp);
              result->ip_ext = sr_get_interface(sr, NAT_OUT)->ip;
          }
          /*ip_hdr->ip_src = result->ip_ext; */
          printf("hey ip_src: \n");
          print_addr_ip_int(result->ip_ext);
          ip_hdr->ip_src = result->ip_ext;
          icmp_hdr->icmp_id = result->aux_ext;



       }else if(strncmp(interface, NAT_OUT, sr_IFACE_NAMELEN)==0){
          /* outside to inside*/

          result = sr_nat_lookup_external(nat, icmp_hdr->icmp_id, nat_mapping_icmp);

          if (!result){
            printf("outside to inside not found \n");
            return;
          }
          ip_hdr->ip_dst = result->ip_int;
          icmp_hdr->icmp_id = result->aux_int;


       }else{
         printf("Nat unreacheable \n");
         send_icmp_3(sr, 3, 3, packet,len);
         return;
       }

       icmp_hdr->icmp_sum = 0;
       icmp_hdr->icmp_sum = cksum(icmp_hdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
       ip_hdr->ip_sum = 0;
       ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

    }else if (protocol ==ip_protocol_tcp){
       printf("Nat with TCP\n");



    }else{
      printf("Nat with unsupported protocol\n");
      return;
    }
    pthread_mutex_unlock(&(sr->nat.lock));
}
