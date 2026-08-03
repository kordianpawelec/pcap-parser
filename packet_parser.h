#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdint.h>


typedef enum {
    ETHERTYPE_UNKNOWN,
    ETHERTYPE_IPV4,
    ETHERTYPE_IPV6,
    ETHERTYPE_VLAN,
    ETHERTYPE_LLDP,
    ETHERTYPE_ARP
} ethernet_type;

typedef enum{
    PCAP_LINKTYPE_UNKNOWN  = 0,
    PCAP_LINKTYPE_ETHERNET = 1,
    PCAP_LINKTYPE_RAW      = 101,
    PCAP_LINKTYPE_WIFI     = 105
} pcap_link_type;

typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t sqc_n;
    uint32_t ack_n;
    uint8_t data_offset_reserved;
    uint8_t flags; //cwr_ece_urg_ack_psh_rst_syn_fin
    uint16_t window;
    uint16_t checksum;
    uint16_t u_ptr;
    uint32_t optional;
} tcp_headers;


typedef struct
{
    uint8_t version_ihl;
    uint8_t tos;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_fragment;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t header_checksum;
    uint32_t src_addr;
    uint32_t dst_addr;
} ipv4_headers;

typedef struct 
{
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snap_length;
    uint32_t ethernet_type;
} pcap_headers;

typedef struct 
{
    uint32_t timestamp_seconds;
    uint32_t timestamp_fraction;
    uint32_t capture_length;
    uint32_t original_length;
} packet_record_headers;

typedef struct
{
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint16_t ethernet_type;
} ethernet_headers;



pcap_headers parse_pcap_header(unsigned char* buff);
ethernet_headers parse_ethernet_header(unsigned char *buff);
ipv4_headers parse_ipv4_header(unsigned char *buff);
packet_record_headers parse_packet_header(unsigned char* buff);
tcp_headers parse_tcp_header(unsigned char *buff);

