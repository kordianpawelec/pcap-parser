#include "packet_parser.h"

ipv4_headers parse_ipv4_header(unsigned char *buff)
{
    ipv4_headers ipv4;

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

    return ipv4;
}


tcp_headers parse_tcp_header(unsigned char *buff)
{
    tcp_headers tcp;
    tcp.src_port = ((uint16_t)buff[0] << 8) | ((uint16_t)buff[1]);
    tcp.dst_port = ((uint16_t)buff[2] << 8) | ((uint16_t)buff[3]);
    tcp.sqc_n = ((uint32_t)buff[4] << 24) | ((uint32_t)buff[5] << 16) | ((uint32_t)buff[6] << 8) | ((uint32_t)buff[7]);
    tcp.ack_n = ((uint32_t)buff[8] << 24) | ((uint32_t)buff[9] << 16) | ((uint32_t)buff[10] << 8) | ((uint32_t)buff[11]);
    tcp.data_offset_reserved = ((uint8_t)buff[12]);
    tcp.flags = ((uint8_t)buff[13]);
    tcp.window = ((uint16_t)buff[14] << 8) | ((uint16_t)buff[15]);
    tcp.checksum = ((uint16_t)buff[16] << 8) | ((uint16_t)buff[17]);
    tcp.u_ptr = ((uint16_t)buff[18] << 8) | ((uint16_t)buff[19]);
    return tcp;
}

ethernet_headers parse_ethernet_header(unsigned char *buff)
{
    ethernet_headers ethernet;
    for (int i = 0; i < 6; i++)
    {
        ethernet.dst_mac[i] = buff[i];
        ethernet.src_mac[i] = buff[i + 6];
    }
    
    uint16_t link =
        ((uint16_t)buff[12]) << 8 |
        ((uint16_t)buff[13]);
    
    if (link == 0x0800)
        ethernet.ethernet_t = ETHERTYPE_IPV4;
    else if (link == 0x0806)
        ethernet.ethernet_t = ETHERTYPE_ARP;
    else if (link == 0x86DD)
        ethernet.ethernet_t = ETHERTYPE_IPV6;
    else if (link == 0x8100)
        ethernet.ethernet_t = ETHERTYPE_VLAN;
    else if (link == 0x88CC)
        ethernet.ethernet_t = ETHERTYPE_LLDP;
    else
        ethernet.ethernet_t = ETHERTYPE_UNKNOWN;

    return ethernet;
}

pcap_headers parse_pcap_header(unsigned char* buff)
{    
    pcap_headers header;

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

    uint32_t type =
        ((uint32_t)buff[23] << 24) |
        ((uint32_t)buff[22] << 16) |
        ((uint32_t)buff[21] << 8)  |
        ((uint32_t)buff[20]);
    
    switch (type)
    {
    case PCAP_LINKTYPE_ETHERNET:
        header.pcap_link_type = PCAP_LINKTYPE_ETHERNET;
        break;
    case PCAP_LINKTYPE_WIFI:
        header.pcap_link_type = PCAP_LINKTYPE_WIFI;
        break;
    case PCAP_LINKTYPE_RAW:
        header.pcap_link_type = PCAP_LINKTYPE_RAW;
        break;
    default:
        header.pcap_link_type = PCAP_LINKTYPE_UNKNOWN;
        break;
    }
    return header;
}

packet_record_headers parse_packet_header(unsigned char* buff)
{     
    packet_record_headers packet_header;

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
    return packet_header;
}
