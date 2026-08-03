#include "state_machine.h"
#include "utils.h"
#include "pcap_ipv4.h"
#include <stdio.h>



//For now we only care about ethernet_type
int process_pcap(FILE *p)
{
    static unsigned char buff[65535];
    int code = 0;

    if(load_buffer(p, buff, 24) == -1)
        return -1;

    if(is_little_indian(buff) == -1)
        return -1;
    
    pcap_headers pcap_header = parse_pcap_header(buff);

    switch (pcap_header.ethernet_type)
    {
    case PCAP_LINKTYPE_ETHERNET:
        code = ethernet_type_ipv4(p, buff);
        if(code == -1)
            return -1;
        break;
    
    case PCAP_LINKTYPE_UNKNOWN:
        printf("Unsupported type of Ethernet type");
        return -1;
        break;
    }
    return 0;
}


int ethernet_type_ipv4(FILE *p, unsigned char *buff)
{
    while(!load_buffer(p, buff, 16))
    {
        packet_record_headers packet_record = parse_packet_header(buff);
        size_t payload_size = packet_record.capture_length;

        if (load_buffer(p, buff, payload_size))
            return -1;
        
        ethernet_headers ethernet_packet = parse_ethernet_header(buff);

        switch (ethernet_packet.ethernet_type)
        {
        case ETHERTYPE_IPV4:
            if(read_ipv4_packet(buff, packet_record) == -1)
                return -1;
            break;
        
        case ETHERTYPE_UNKNOWN:
            printf("\n\n\n Skipping start");
            printf("\n\n\n Skipping end");
            continue;
        }
    }
    return 0;
}
