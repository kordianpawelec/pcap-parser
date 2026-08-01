
#include "packet_parser.h"
#include "reader.h"

static unsigned char buff[24];
int buff_idx = 0;



int main(int argc, char const *argv[])
{

    const char* file_name = "smallFlows.pcap";

    FILE *p = openfile(file_name);

    if (p == NULL) {
        printf("Cant open file");
        return 1;
    }

    if(!read_file(p, buff, 24)){
        printf("Cant read the PCAP!");
        fclose(p);
        return 1;
    }

    if (is_little_indian(buff))
    {
        printf("Little-endin PCAP\n");
    }
    else 
    {
        printf("returning cant support non Little Indian\n");
        return 1;
    }

    parse_pcap_headers(buff);


    if(!read_file(p, buff, 16)){
        printf("Cant read packer headers!");
        fclose(p);
        return 1;
    }
    
    size_t next_packet_size = parse_packet_header(buff).capture_length;

    unsigned char *packet_buff = malloc((size_t)next_packet_size);
    if(packet_buff == NULL)
    {
        printf("Memory allocation failed\n");
        fclose(p);
        return 1;
    }

    if(!read_file(p, packet_buff, next_packet_size))
    {
        printf("Could not read packet\n!");
        fclose(p);
        return 1;
    }

    parse_ethernet_header(packet_buff);
    buff_idx += 14;
    ipv4_header ipv4 = parse_ipv4_header(packet_buff + buff_idx);
    size_t ipv4_l = (ipv4.version_ihl & 0x0f) * 4;
    buff_idx += ipv4_l;

    tcp_header tcp = parse_tcp_header(packet_buff + buff_idx);

    free(packet_buff);
        
    fclose(p);
    return 0;
}



