
#include "utils.h"
#include "state_machine.h"

int buff_idx = 0;



int main(void)
{
    const char* file_name = "smallFlows.pcap";
    FILE *p = open_file(file_name);
    if (p == NULL)
        return 1;


    int status = process_pcap(p);
    if (status == -1)
    {
        fprintf(stderr, "Closing a program\n");
        fclose(p);
        return 1;
    }
    fclose(p);
    return 0;
}
