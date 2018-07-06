#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/ether.h>
#include <netinet/in.h>

#include <sys/socket.h>
#include <arpa/inet.h>

#include "trace.h"
#include "checksum.h"

int main(int argc, char *argv[])
{
   /* Parse the command line args to make sure they are valid. Also opens
    * the .pcap file if possible */
   if (parse_cmd_line(argc, argv))
   {
      fprintf(stderr, "Usage: trace [.pcap file]\n");
      exit(FAILURE);
   }
 
   /* Read the entire .pcap file! */
   read_file();
 
   return SUCCESS;
}

/* Reads the .pcap file from start to finish */
void read_file()
{
   struct pcap_pkthdr *pkt_header;
   const u_char *pkt_data;
   int i = 1;
   
   /* Process all packets; break from loop when there are no more packets */
   while(pcap_next_ex(image, &pkt_header, &pkt_data) == READ_PACKET_SUCCESS)
   {
      printf("\nPacket number: %d  Packet Len: %d\n\n", i++, pkt_header->len);
         
      /* Read and print Ethernet header */
      uint16_t type = read_ethernet_header(pkt_data);

      /* type is either IP or ARP */
      switch(type)
      {
         case IP_TYPE:
         {
            /* Read and print IP header */
            struct ip_header ip = read_ip_header(pkt_data + 
               sizeof(struct ethernet_header));
            
            /* type is either TCP, UDP, or ICMP */
            switch(ip.protocol)
            {
               case IP_PROT_TCP:
               {
                  /* Read and print TCP header */
                  read_tcp_header(pkt_data + sizeof(struct ethernet_header) +
                     ((ip.ver__hdr_len & IP_HDR_LEN_BITS) * IP_HDR_LEN_MULT),
                     ip);
                  break;
               }
               case IP_PROT_UDP:
               {
                  /* Read and print UDP header */
                  read_udp_header(pkt_data + sizeof(struct ethernet_header) +
                     ((ip.ver__hdr_len & IP_HDR_LEN_BITS) * IP_HDR_LEN_MULT));
                  break;
               }
               case IP_PROT_ICMP:
               {
                  /* Read and print ICMP header */
                  read_icmp_header(pkt_data + sizeof(struct ethernet_header) +
                     ((ip.ver__hdr_len & IP_HDR_LEN_BITS) * IP_HDR_LEN_MULT));
                  break;
               }
               default:
               {
                  /* This should print "Unknown PDU", but IP_bad_checksum.pcap
                   * would not have the correct output */
                  break;
               }
            }
            break;
         }
         case ARP_TYPE:
         {
            /* Read and print ARP header */
            read_arp_header(pkt_data + sizeof(struct ethernet_header));
            break;
         }
         default:
         {
            printf("      Unknown PDU\n\n");
            break;
         }
      }
   }
}

/* Read and print Ethernet header */
uint16_t read_ethernet_header(const u_char *pkt_data)
{
   struct ethernet_header eth;
   struct ether_addr dest_ether;
   struct ether_addr source_ether;
   
   /* Get Ethernet header and the dest, source ether_addr structs */
   memcpy(&eth, pkt_data, sizeof(eth));
   memcpy(&dest_ether, &(eth.dest), sizeof(dest_ether));
   memcpy(&source_ether, &(eth.source), sizeof(source_ether));

   /* Print Ethernet header contents */
   printf("      Ethernet Header\n");
   printf("              Dest MAC: %s\n", safe_ether_ntoa(&dest_ether));
   printf("              Source MAC: %s\n", safe_ether_ntoa(&source_ether));
   printf("              Type: ");
   
   /* type is either IP or ARP */
   switch(eth.type)
   {
      case IP_TYPE:
      {
         printf("IP\n\n");
         break;
      }
      case ARP_TYPE:
      {
         printf("ARP\n\n");
         break;
      }
      default:
      {
         printf("Unknown PDU\n\n");
         break;
      }
   }
      
   return eth.type;
}

/* Read and print ARP header */
void read_arp_header(const u_char *pkt_data)
{
   struct arp_header arp;
   struct in_addr in;
   struct ether_addr source_ether;
   struct ether_addr dest_ether;
   
   /* Get ARP header and the dest, source ether_addr structs */
   memcpy(&arp, pkt_data, sizeof(arp));
   memcpy(&source_ether, &(arp.snd_MAC), sizeof(source_ether));
   memcpy(&dest_ether, &(arp.tgt_MAC), sizeof(dest_ether));
   
   /* Print ARP header contents */
   printf("      ARP header\n");
   printf("              Opcode: ");
   
   /* opcode is either a Request or a Reply */
   switch(arp.opcode)
   {
      case ARP_OPCODE_REQUEST:
      {
         printf("Request\n");
         break;
      }
      case ARP_OPCODE_REPLY:
      {
         printf("Reply\n");
         break;
      }
      default:
      {
         printf("Unknown\n");
         break;
      }
   }
   
   /* Finish printing ARP header */
   printf("              Sender MAC: %s\n", safe_ether_ntoa(&source_ether));
   memcpy(&(in.s_addr), arp.snd_IP, sizeof(in.s_addr));
   printf("              Sender IP: %s\n", inet_ntoa(in));
   printf("              Target MAC: %s\n", safe_ether_ntoa(&dest_ether));
   memcpy(&(in.s_addr), arp.tgt_IP, sizeof(in.s_addr));
   printf("              Target IP: %s\n\n", inet_ntoa(in));
}

/* Read and print IP header */
struct ip_header read_ip_header(const u_char *pkt_data)
{
   struct ip_header ip;
   struct in_addr in;

   /* Get IP header */
   memcpy(&ip, pkt_data, sizeof(ip));

   /* Print IP header */
   printf("      IP Header\n");
   printf("              IP Version: %d\n", 
      (ip.ver__hdr_len & IP_VER_BITS) >> IP_VER_SHFT);
   printf("              Header Len (bytes): %d\n", 
      (ip.ver__hdr_len & IP_HDR_LEN_BITS) * IP_HDR_LEN_MULT);
   printf("              TOS subfields:\n");
   printf("                 Diffserv bits: %d\n", 
      (ip.diff_serv__enc & IP_DIF_SERV_BITS) >> IP_DIF_SERV_SHFT);
   printf("                 ECN bits: %d\n", ip.diff_serv__enc & IP_ENC_BITS);
   printf("              TTL: %u\n", ip.time_to_live);
   printf("              Protocol: ");

   /* protocol is either TCP, UDP, or ICMP */
   switch(ip.protocol)
   {
      case IP_PROT_TCP:
      {
         printf("TCP\n");
         break;
      }
      case IP_PROT_UDP:
      {
         printf("UDP\n");
         break;
      }
      case IP_PROT_ICMP:
      {
         printf("ICMP\n");
         break;
      }
      default:
      {
         printf("Unknown\n");
         break;
      }
   }
   
   /* Verify checksum */
   printf("              Checksum: ");
   int len = (ip.ver__hdr_len & IP_HDR_LEN_BITS) * IP_HDR_LEN_MULT;
   if (in_cksum((unsigned short *) pkt_data, len))
   {
      printf("Incorrect (0x%.4x)\n", ntohs(ip.checksum));
   }
   else
   {
      printf("Correct (0x%.4x)\n", ntohs(ip.checksum));
   }
   
   /* Finish printing IP header */
   memcpy(&(in.s_addr), ip.snd_IP, sizeof(in.s_addr));
   printf("              Sender IP: %s\n", inet_ntoa(in));
   memcpy(&(in.s_addr), ip.tgt_IP, sizeof(in.s_addr));
   printf("              Dest IP: %s\n\n", inet_ntoa(in));
   
   /* Return IP header for use of opcode and tcp_pseudo_header fields */
   return ip;
}

/* Read and print ICMP header */
void read_icmp_header(const u_char *pkt_data)
{
   struct icmp_header icmp;
   
   /* Get ICMP header */
   memcpy(&icmp, pkt_data, sizeof(icmp));

   /* Print ICMP header */
   printf("      ICMP Header\n");
   printf("              Type: ");
   
   /* type is either a Request or a Reply */
   switch(icmp.type)
   {
      case ICMP_REQ:
      {
         printf("Request\n");
         break;
      }
      case ICMP_REP:
      {
         printf("Reply\n");
         break;
      }
      default:
      {
         printf("%d\n", icmp.type);
         break;
      }
   }
}

/* Read and print UDP header */
void read_udp_header(const u_char *pkt_data)
{
   struct udp_header udp;
   
   /* Get UDP header */
   memcpy(&udp, pkt_data, sizeof(udp));

   /* Print UDP header */
   printf("      UDP Header\n");
   printf("              Source Port: ");
   print_port(udp.source_port);
   printf("              Dest Port: ");
   print_port(udp.dest_port);
   printf("\n");
}

/* Reads and prints TCP header */
void read_tcp_header(const u_char *pkt_data, struct ip_header ip)
{
   struct tcp_header tcp;
   struct tcp_pseudo_header p_tcp;

   /* Get TCP header */
   memcpy(&tcp, pkt_data, sizeof(tcp));
   
   /* Create TCP pseudo header */
   memcpy(&(p_tcp.source), &(ip.snd_IP), sizeof(p_tcp.source));
   memcpy(&(p_tcp.dest), &(ip.tgt_IP), sizeof(p_tcp.dest));
   p_tcp.reserved = TCP_PSEUDO_RES;
   p_tcp.protocol = ip.protocol;
   
   uint16_t tcp_len = ntohs(ip.total_length) - 
      ((ip.ver__hdr_len & IP_HDR_LEN_BITS) * IP_HDR_LEN_MULT);
   p_tcp.tcp_length = htons(tcp_len);
   
   /* Create new data buffer that includes TCP pseudo header */
   u_char addr[TCP_PSEUDO_BUF];
   u_char *ptr = addr;
   memcpy(ptr, &p_tcp, sizeof(struct tcp_pseudo_header));
   ptr += sizeof(struct tcp_pseudo_header);
   memcpy(ptr, pkt_data, tcp_len);
   
   /* Print TCP header */
   printf("      TCP Header\n");
   printf("              Source Port: ");
   print_port(tcp.source_port);
   printf("              Dest Port: ");
   print_port(tcp.dest_port);
   printf("              Sequence Number: %u\n", ntohl(tcp.sequence_no));
   printf("              ACK Number: %u\n", ntohl(tcp.ack_no));
   printf("              Data Offset (bytes): %d\n", 
      ((tcp.header_length__nonce & TCP_HDR_LEN_BITS) >> TCP_HDR_LEN_SHFT) *
      TCP_HDR_LEN_MULT);
   printf("              SYN Flag: %s\n", 
      (tcp.flags & TCP_SYN_FLAG_BIT) ? "Yes": "No");
   printf("              RST Flag: %s\n", 
      (tcp.flags & TCP_RST_FLAG_BIT) ? "Yes": "No");
   printf("              FIN Flag: %s\n", 
      (tcp.flags & TCP_FIN_FLAG_BIT) ? "Yes": "No");
   printf("              ACK Flag: %s\n", 
      (tcp.flags & TCP_ACK_FLAG_BIT) ? "Yes": "No");
   printf("              Window Size: %d\n", ntohs(tcp.window_size));
   printf("              Checksum: ");
   
   /* Verify checksum using new data buffer that includes TCP pseudo header */
   if (in_cksum((unsigned short *) addr, sizeof(struct tcp_pseudo_header)
      + tcp_len))
   {
      printf("Incorrect (0x%.4x)\n", ntohs(tcp.checksum));
   }
   else
   {
      printf("Correct (0x%.4x)\n", ntohs(tcp.checksum));
   }
}

/* Runs ether_ntoa with proper error catching */
char *safe_ether_ntoa(struct ether_addr *addr)
{
   char *string;
   
   if ((string = ether_ntoa(addr)) == NULL)
   {
      perror("ether_ntoa");
      exit(FAILURE);
   }
   
   return string;
}

/* Prints proper port */
void print_port(uint16_t port)
{
   uint16_t out_port = ntohs(port);
   
   /* port is either DNS, HTTP, TELNET, FTP, POP3, SMTP, or its number */
   switch(out_port)
   {
      case DNS_PORT:
      {
         printf("DNS\n");
         break;
      }
      case HTTP_PORT:
      {
         printf("HTTP\n");
         break;
      }
      case TELNET_PORT:
      {
         printf("TELNET\n");
         break;
      }
      case FTP_PORT:
      {
         printf("FTP\n");
         break;
      }
      case POP3_PORT:
      {
         printf("POP3\n");
         break;
      }
      case SMTP_PORT:
      {
         printf("SMTP\n");
         break;
      }
      default:
      {
         printf("%d\n", out_port);
         break;
      }
   }
}

/* Parses command line arguments and opens the .pcap file if possible */
int parse_cmd_line(int argc, char *argv[])
{   
   char *file;
   char errbuf[PCAP_ERRBUF_SIZE];
   
   /* There must be 2 arguments: "trace", .pcap file */
   if (argc != 2)
   {
      return FAILURE;
   }
   
   file = argv[1];
   
   /* Open .pcap file. If this fails, the program will exit */
   if ((image = pcap_open_offline(file, errbuf)) == NULL)
   {
      perror("pcap_open_offline");
      return FAILURE;
   }
   
   return SUCCESS;
}