#include "utils.h"


int read_record_packet_header(FILE *p, unsigned char* buff)
{
    size_t size_byte_read = fread(buff, 1, 16, p);

    if (size_byte_read == 16)
        return 1;
    if (size_byte_read == 0 && feof(p))
        return 0;
    fprintf(stderr, "Imcomplete PCAP packet header; read %zu of 16 bytes", size_byte_read);
    return -1;
}

int load_buffer(FILE *p, unsigned char *buff, size_t size)
{

    size_t size_byte_read = fread(buff, 1, size, p);

    if(size_byte_read != size)
    {
        if (ferror(p))
            fprintf(stderr, "Failed to read the file\n");
        else 
            fprintf(stderr, "Error loading in the buffer, truncated file. requesting %zu. Got: %zu\n", size, size_byte_read);
        return -1;
    }
    return 0;
}

FILE *open_file(const char *name)
{

    FILE *p = fopen(name, "rb");

    if (p == NULL) {
        fprintf(stderr, "Cant open file\n");
        return NULL;
    }
    return p;
}

int is_little_indian(const unsigned char * buff)
{
    return (buff[0] == 0xd4 && buff[1] == 0xc3 && buff[2] == 0xb2 && buff[3] == 0xa1) ? 1: -1;
}
