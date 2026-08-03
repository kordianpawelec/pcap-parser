#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdint.h>
#include "string.h"



int load_buffer(FILE *p, unsigned char *buff, size_t size);
FILE *open_file(const char *name);
int is_little_indian(const unsigned char * buff);
