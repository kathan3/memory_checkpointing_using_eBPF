#ifndef __EXEC_H__
#define __EXEC_H__

struct exec_evt {
    pid_t pid;
    pid_t tgid;
    char comm[32];
    char file[32];
};
struct restore_evt {
    pid_t pid;
    long long int vma_start;
    long long int vma_end;
    unsigned char data[4096];
};
#endif // __EXEC_H__
