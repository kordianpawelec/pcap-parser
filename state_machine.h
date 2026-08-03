#include <stdio.h>
#include <stdint.h>

int process_pcap(FILE *p);
int ethernet_type_ipv4(FILE *p, unsigned char *buff);
int skip_unsupported_packet(size_t payload_size, FILE *p);

