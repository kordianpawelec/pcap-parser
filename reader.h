#include <stdio.h>

FILE *openfile(const char *name);
int read_file(FILE *file, unsigned char *buff, int byte_size);
int is_little_indian(const unsigned char * buff);