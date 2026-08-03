#include "pcap_ipv4.h"
#include "utils.h"



int read_ipv4_packet(unsigned char *buff, packet_record_headers records_packet)
{
    size_t idx = 14; //ipv4 header size

    if (records_packet.capture_length < 14 + 20)
    {
        fprintf(stderr, "Packet too short for Ethernet + IPv4\n");
        return -1;
    }

    ipv4_headers ipv4 = parse_ipv4_header(buff + idx);

    if (ipv4.version_ihl >> 4 != 4)
    {
        fprintf(stderr, "Skipping non IPv4 header\n");
        return -1;
    }

    if (ipv4.protocol != 6)
    {
        fprintf(stderr, "Packet is not a TCP payload skipping it\n");
        return 0;
    }

    size_t ipv4_size = (ipv4.version_ihl & 0x0f) * 4;

    if (ipv4_size < 20 || 14 + ipv4_size > records_packet.capture_length)
    {
        fprintf(stderr, "Invalid IPv4 header length\n");
        return -1;
    }

    if((ipv4.flags_fragment & 0x1FFF) != 0 || ((ipv4.flags_fragment & 0x2000) != 0))
    {
        fprintf(stderr, "Skipping fragmentation packet for now\n");
        return 0;
    }

    idx += ipv4_size;

    if (idx + 20 > records_packet.capture_length)
    {
        fprintf(stderr, "Packet too short for TCP\n");
        return -1;
    }

    if (!(14 + ipv4.total_length <= records_packet.capture_length))
    {
        fprintf(stderr, "Invalid IPv4 packet size\n");
        return -1;
    }

    tcp_headers tcp = parse_tcp_header(buff + idx);

    size_t tcp_size = ((tcp.data_offset_reserved) >> 4) * 4;

    if (tcp_size < 20 || idx + tcp_size > records_packet.capture_length)
    {
        fprintf(stderr, "Invalid TCP header size\n");
        return -1;    
    }

    idx += tcp_size;

    if (ipv4.total_length < ipv4_size + tcp_size)
    {
        fprintf(stderr, "Invalid IPv4/TCP lengths\n");
        return -1;
    }

    size_t payload_size = ipv4.total_length - ipv4_size - tcp_size;

    if (payload_size == 0)
        return 0;
    
    if (idx + payload_size > records_packet.capture_length)
    {
        fprintf(stderr, "TCP payload exceedes capured packet\n");
        return -1;
    }


    //Parse packet details as it is
    for (size_t i = 0; i < payload_size; i++)
    {
        unsigned char byte = buff[idx + i];

        if (isprint(byte) || byte == '\r' || byte == '\n' || byte == '\t')
            putchar(byte);
        else
            putchar('.');
    }
    printf("_______________________________________________________________________________________________\n");
    return 0;
}
