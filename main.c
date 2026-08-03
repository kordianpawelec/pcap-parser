
#include "utils.h"
#include "state_machine.h"

int buff_idx = 0;



int main(void)
{
    const char* file_name = "smallFlows.pcap";
    FILE *p = open_file(file_name);
    if (p == NULL)
        return 1;


    int return_code = process_pcap(p);
    if (return_code == -1)
        return 1;

    return 0;
}
