#include "pcap_ipv4.h"
#include "utils.h"



int read_ipv4_packet(unsigned char *buff, packet_record_headers records_packet)
{
    size_t idx = 14;

    ipv4_headers ipv4 = parse_ipv4_header(buff + idx);

    size_t ipv4_size = (ipv4.version_ihl & 0x0f) * 4;
    idx += ipv4_size;

    if (ipv4.protocol != 6)
        return 0;

    tcp_headers tcp = parse_tcp_header(buff + idx);
    size_t tcp_size = ((tcp.data_offset_reserved) >> 4) * 4;

    if (tcp.flags == 0x002)
        return 0;
    if (tcp.flags == 0x010)
        return 0;
    if (tcp.flags == 0x011)
        return 0;
    if (tcp.flags == 0x002)
        return 0;
    if (tcp.flags == 0x014)
        return 0;
    if (tcp.flags == 0x018)
        return 0;

    idx += tcp_size;

    if (tcp_size < 20 || idx > records_packet.capture_length)
    {
        fprintf(stderr, "Invalid TCP header size\n");
        return -1;    
    }

    size_t payload_size = ipv4.total_length - ipv4_size - tcp_size;


    if(ipv4.total_length < ipv4_size + tcp_size)
    {
        fprintf(stderr, "Invalid IPv4/TCP size\n");
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
