#include "state_machine.h"
#include "utils.h"
#include "pcap_ipv4.h"
#include <stdio.h>



//For now we only care about ethernet_type
int process_pcap(FILE *p)
{
    static unsigned char buff[65535];
    int status = 0;

    if(load_buffer(p, buff, 24) == -1)
        return -1;

    if(is_little_indian(buff) == -1)
        return -1;
    
    pcap_headers pcap_header = parse_pcap_header(buff);

    switch (pcap_header.pcap_link_type)
    {
    case PCAP_LINKTYPE_ETHERNET:
        status = ethernet_type_ipv4(p, buff);
        if(status == -1)
            return -1;
        break;
    
    case PCAP_LINKTYPE_UNKNOWN:
        printf("Unsupported type of Ethernet type\n");
        return -1;
        break;
    default:
     break;
    }
    return 0;
}


int ethernet_type_ipv4(FILE *p, unsigned char *buff)
{
    while(1)
    {
        int status = read_record_packet_header(p, buff);

        if (status == 0)
            break;
        if (status == -1)
            return -1;
        
        packet_record_headers packet_record = parse_packet_header(buff);

        size_t payload_size = packet_record.capture_length;

        if(payload_size > 65535)
        {
            fprintf(stderr, "Error the packet data size(%zu) is bigger then the buffr szie of 65535", payload_size);
            return -1;
        }

        if (load_buffer(p, buff, payload_size))
            return -1;

        ethernet_headers ethernet_packet = parse_ethernet_header(buff);

        switch (ethernet_packet.ethernet_t)
        {
        case ETHERTYPE_IPV4:
            if(read_ipv4_packet(buff, packet_record) == -1)
                return -1;
            break;
        
        case ETHERTYPE_UNKNOWN:
            printf("\n\n\n Skipping start");
            printf("\n\n\n Skipping end");
            continue;
        default:
            continue;
        }
    }
    return 0;
}
