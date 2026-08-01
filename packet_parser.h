#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdint.h>

typedef enum
{
    ETHERNET,
    TCP,
    IPV4,
    UDP
} link_type;

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
} ipv4_header;

typedef struct 
{
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snap_length;
    uint32_t link_type;
} headers;

typedef struct 
{
    uint32_t timestamp_seconds;
    uint32_t timestamp_fraction;
    uint32_t capture_length;
    uint32_t original_length;
} packet_header_16_bytes;

typedef struct
{
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint16_t ethernet_type;
} ethernet_header_14bytes;


void parse_arp(unsigned char *buff);
void parse_ipv6(unsigned char *buff);
ipv4_header parse_ipv4_header(unsigned char *buff);
packet_header_16_bytes parse_packet_header(unsigned char* buff);
void parse_pcap_headers(unsigned char* buff);
void parse_ethernet_header(unsigned char *buff);

