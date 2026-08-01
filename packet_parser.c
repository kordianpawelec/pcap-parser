#include "packet_parser.h"

ipv4_header parse_ipv4_header(unsigned char *buff)
{
    ipv4_header ipv4;

    ipv4.version_ihl = buff[0];
    ipv4.tos = buff[1];

    ipv4.total_length =
        ((uint16_t)buff[2] << 8) |
        (uint16_t)buff[3];

    ipv4.identification =
        ((uint16_t)buff[4] << 8) |
        (uint16_t)buff[5];

    ipv4.flags_fragment =
        ((uint16_t)buff[6] << 8) |
        (uint16_t)buff[7];

    ipv4.ttl = buff[8];
    ipv4.protocol = buff[9];

    ipv4.header_checksum =
        ((uint16_t)buff[10] << 8) |
        (uint16_t)buff[11];

    ipv4.src_addr =
        ((uint32_t)buff[12] << 24) |
        ((uint32_t)buff[13] << 16) |
        ((uint32_t)buff[14] << 8)  |
        (uint32_t)buff[15];

    ipv4.dst_addr =
        ((uint32_t)buff[16] << 24) |
        ((uint32_t)buff[17] << 16) |
        ((uint32_t)buff[18] << 8)  |
        (uint32_t)buff[19];

    uint32_t src_adr1 = ipv4.src_addr >> 24;
    uint32_t src_adr2 = ipv4.src_addr << 8 >> 24;
    uint32_t src_adr3 = ipv4.src_addr << 16 >> 24;
    uint32_t src_adr4 = ipv4.src_addr << 24 >> 24;

    uint32_t dst_adr1 = ipv4.dst_addr >> 24;
    uint32_t dst_adr2 = ipv4.dst_addr << 8 >> 24;
    uint32_t dst_adr3 = ipv4.dst_addr << 16 >> 24;
    uint32_t dst_adr4 = ipv4.dst_addr << 24 >> 24;

    u_int8_t version = ipv4.version_ihl >> 4;
    uint8_t ihl = ipv4.version_ihl & 0x0f;


    printf("\n\n\n");
    printf("version                 %u\n", version);
    printf("ihl                     %u\n", ihl);
    printf("total length            %u\n", ipv4.total_length);
    printf("identification          %u\n", ipv4.identification);
    printf("flags                   %u\n", (ipv4.flags_fragment >> 13) & 0x07);
    printf("fragments               %u\n", ipv4.flags_fragment & 0x1fff);
    printf("ttl                     %u\n", ipv4.ttl);
    printf("protocol                %u\n", ipv4.protocol);
    printf("header checksum         %u\n", ipv4.header_checksum);
    printf("SRC ADDR:               %u.%u.%u.%u\n", src_adr1, src_adr2, src_adr3, src_adr4 );
    printf("DST ADDR:               %u.%u.%u.%u\n", dst_adr1, dst_adr2, dst_adr3, dst_adr4 );

    return ipv4;
}

void parse_ipv6(unsigned char *buff)
{

}

void parse_arp(unsigned char *buff)
{

}

void parse_ethernet_header(unsigned char *buff)
{
    ethernet_header_14bytes ethernet;

    for (int i = 0; i < 6; i++)
    {
        ethernet.dst_mac[i] = buff[i];
        ethernet.src_mac[i] = buff[i + 6];
    }


    ethernet.ethernet_type =
        ((uint16_t)buff[12]) << 8 |
        ((uint16_t)buff[13]);

    
    printf("DST MAC:                ");
    for (int i = 0; i < 6; i++)
    {
        if (i > 0) {
            printf(":");
        }
        printf("%02x", ethernet.dst_mac[i]);
    }
    printf("\n");

    printf("SRC MAC:                ");
    for (int i = 0; i < 6; i++)
    {
        if (i > 0) {
            printf(":");
        }

        printf("%02x", ethernet.src_mac[i]);

    }
    printf("\n");

    printf("ETHERNET TYPE:          %u\n", ethernet.ethernet_type);

}

void parse_pcap_headers(unsigned char* buff)
{    
    headers header;

    header.magic_number =
        ((uint32_t)buff[3] << 24)  |
        ((uint32_t)buff[2] << 16)  |
        ((uint32_t)buff[1] << 8)   |
        ((uint32_t)buff[0]);

    header.version_major = 
        ((uint16_t)buff[5] << 8)   |
        ((uint16_t)buff[4]);
    
    header.version_minor =
        ((uint16_t)buff[7] << 8)   |
        ((uint16_t)buff[6]);

    uint32_t timezone = 
        ((uint32_t)buff[11] << 24)  |
        ((uint32_t)buff[10] << 16)  |
        ((uint32_t)buff[9] << 8)    |
        ((uint32_t)buff[8]);
    header.thiszone = (int32_t)timezone;

    header.sigfigs =
        ((uint32_t)buff[15] << 24) |
        ((uint32_t)buff[14] << 16) |
        ((uint32_t)buff[13] << 8)  |
        ((uint32_t)buff[12]);

    header.snap_length =
        ((uint32_t)buff[19] << 24) |
        ((uint32_t)buff[18] << 16) |
        ((uint32_t)buff[17] << 8)  |
        ((uint32_t)buff[16]);

    header.link_type =
        ((uint32_t)buff[23] << 24) |
        ((uint32_t)buff[22] << 16) |
        ((uint32_t)buff[21] << 8)  |
        ((uint32_t)buff[20]);

    
        printf("Magic number:       0x%08x\n", header.magic_number);
        printf("Version:            %u.%u\n", header.version_major, header.version_minor);
        printf("Timezone:           %d\n", header.thiszone);
        printf("Sigfigs:            %u\n", header.sigfigs);
        printf("Snap length:        %u\n", header.snap_length);
        printf("Link type:          %u\n", header.link_type);
        printf("\n\n\n");

}

packet_header_16_bytes parse_packet_header(unsigned char* buff)
{     
    packet_header_16_bytes packet_header;

    packet_header.timestamp_seconds =
        ((uint32_t)buff[3] << 24)    |
        ((uint32_t)buff[2] << 16)    |
        ((uint32_t)buff[1] << 8)     |
        ((uint32_t)buff[0]);

    packet_header.timestamp_fraction =

        ((uint32_t)buff[7] << 24)    |
        ((uint32_t)buff[6] << 16)    |
        ((uint32_t)buff[5] << 8)     |
        ((uint32_t)buff[4]);
    
    packet_header.capture_length =

        ((uint32_t)buff[11] << 24)   |
        ((uint32_t)buff[10] << 16)   |
        ((uint32_t)buff[9] << 8)     |
        ((uint32_t)buff[8]);
    packet_header.original_length =

        ((uint32_t)buff[15] << 24)   |
        ((uint32_t)buff[14] << 16)   |
        ((uint32_t)buff[13] << 8)    |
        ((uint32_t)buff[12]);

        printf("timestamp_seconds:  %d\n", packet_header.timestamp_seconds);
        printf("timestamp_fraction: %u\n", packet_header.timestamp_fraction);
        printf("capture_length:     %u\n", packet_header.capture_length);
        printf("original_length:    %u\n", packet_header.original_length);
        printf("\n\n\n");
    return packet_header;
}