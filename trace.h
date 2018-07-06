#ifndef TRACE_H
   #define TRACE_H

   #include <stdint.h>
   #include <pcap/pcap.h>
   
   #define FAILURE 1
   #define SUCCESS 0
   
   #define READ_PACKET_SUCCESS 1
   
   #define IP_TYPE 8
   #define ARP_TYPE 1544
   
   #define ARP_OPCODE_REQUEST 256
   #define ARP_OPCODE_REPLY 512
   
   #define IP_PROT_TCP 6
   #define IP_PROT_UDP 17
   #define IP_PROT_ICMP 1
   #define IP_HDR_LEN_BITS 0x0F
   #define IP_HDR_LEN_MULT 4
   #define IP_VER_BITS 0xF0
   #define IP_VER_SHFT 4
   #define IP_DIF_SERV_BITS 0xFC
   #define IP_DIF_SERV_SHFT 2
   #define IP_ENC_BITS 0x03

   #define ICMP_REQ 8
   #define ICMP_REP 0
   
   #define TCP_PSEUDO_RES 0
   #define TCP_PSEUDO_BUF 1500
   
   #define TCP_HDR_LEN_BITS 0xF0
   #define TCP_HDR_LEN_SHFT 4
   #define TCP_HDR_LEN_MULT 4
   #define TCP_SYN_FLAG_BIT 0x02
   #define TCP_RST_FLAG_BIT 0x04
   #define TCP_FIN_FLAG_BIT 0x01
   #define TCP_ACK_FLAG_BIT 0x10
   
   #define DNS_PORT 53
   #define HTTP_PORT 80
   #define TELNET_PORT 23
   #define FTP_PORT 21
   #define POP3_PORT 110
   #define SMTP_PORT 25
   
   struct __attribute__ ((__packed__)) ethernet_header {
      uint8_t dest[6];   // 48
      uint8_t source[6]; // 48
      uint16_t type;     // 16
   };
   
   struct __attribute__ ((__packed__)) arp_header { 
      uint16_t h_type;    //16
      uint16_t p_type;    //16
      uint8_t h_size;     //8
      uint8_t p_size;     //8
      uint16_t opcode;    //16
      uint8_t snd_MAC[6]; //48
      uint8_t snd_IP[4];  //32
      uint8_t tgt_MAC[6]; //48
      uint8_t tgt_IP[4];  //32
   };
   
   struct __attribute__ ((__packed__)) ip_header { 
      uint8_t ver__hdr_len; // 4, 4
      uint8_t diff_serv__enc;         // 6, 2
      uint16_t total_length;          // 16
      uint16_t id;                    // 16
      uint16_t flags;                 // 16
      uint8_t time_to_live;           // 8
      uint8_t protocol;               // 8
      uint16_t checksum;       // 16
      uint8_t snd_IP[4];  //32
      uint8_t tgt_IP[4];  //32
   };
   
   struct __attribute__ ((__packed__)) icmp_header { 
      uint8_t type;    // 8
      uint8_t code;    // 8
      uint16_t checksum; // 16
      uint16_t id;     // 16
      uint16_t seq;    // 16
   };
   
   struct __attribute__ ((__packed__)) udp_header {
      uint16_t source_port;
      uint16_t dest_port;
      uint16_t length;
      uint16_t checksum;
   };
   
   struct __attribute__ ((__packed__)) tcp_header { 
      uint16_t source_port;         // 16
      uint16_t dest_port;           // 16
      uint32_t sequence_no;         // 32
      uint32_t ack_no;              // 32
      uint8_t header_length__nonce; // 4, 3, 1
      uint8_t flags;                // 1, 1, 1, 1, 1, 1, 1, 1
      uint16_t window_size;         // 16
      uint16_t checksum;            // 16
      //uintANY_t payload;  
   };
   
   struct __attribute__ ((__packed__)) tcp_pseudo_header { 
      uint8_t source[4];
      uint8_t dest[4];
      uint8_t reserved;
      uint8_t protocol;
      uint16_t tcp_length;
   };
   
   pcap_t *image;
   
   int parse_cmd_line(int argc, char *argv[]);
   void read_file();
   uint16_t read_ethernet_header();   
   void read_arp_header(const u_char *pkt_data);
   struct ip_header read_ip_header(const u_char *pkt_data);
   void read_icmp_header(const u_char *pkt_data);
   void read_udp_header(const u_char *pkt_data);
   void read_tcp_header(const u_char *pkt_data, struct ip_header ip);
   
   void print_port(uint16_t port);
   char *safe_ether_ntoa(struct ether_addr *addr);
#endif