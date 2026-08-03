#include "utils.h"


int load_buffer(FILE *p, unsigned char *buff, size_t size)
{
    if(fread(buff, 1, size, p) == 0)
    {
        fprintf(stderr, "Error loading in the buffer\n");
        fclose(p);
        return -1;
    }

    return 0;
}

FILE *open_file(const char *name)
{

    FILE *p = fopen(name, "rb");

    if (p == NULL) {
        fprintf(stderr, "Cant open file");
        return NULL;
    }
    return p;
}

int is_little_indian(const unsigned char * buff)
{
    return buff[0] == 0xd4 && buff[1] == 0xc3 && buff[2] == 0xb2 && buff[3] == 0xa1;
}
