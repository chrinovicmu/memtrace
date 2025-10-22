#ifndef MALLOC_TRACE_H
#define MALLOC_TRACE_H

#include <linux/types.h>

#define COMMAND_LEN     16 
#define MESSAGE_LEN     12
#define PATH_LEN        16 

struct data_t
{
    u32 pid; 
    u32 uid; 
    u64 ts; 
    u64 bytes_alloc; 
    u64 bytes_freed; 
    int cpu; 
    char command[COMMAND_LEN]; 
    char message[MESSAGE_LEN; 
    char path[PATH_LEN; 
}; 




#endif 
