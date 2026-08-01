#include "reader.h"

FILE *openfile(const char *name)
{
    FILE *file = fopen(name, "rb");
    if (file != NULL){
        return file;
    }

    return NULL;
}

int read_file(FILE *file, unsigned char *buff, int byte_size)
{
    if (fread(buff, 1, byte_size, file) == 0) {
        return 0;
    }
    return 1;
}

int is_little_indian(const unsigned char * buff)
{
    return buff[0] == 0xd4 && buff[1] == 0xc3 && buff[2] == 0xb2 && buff[3] == 0xa1;
}