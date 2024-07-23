#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "exec.h"
pid_t pid = -1;
int read_done = 0;
int write_done = 0;
int ready_to_check=0;
unsigned long long int len = 0;
unsigned long long int addr;
int valid = 0;
int pages = -0;
struct oo{
    unsigned char data[256];
};
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
        __type(key, u32);
        __type(value, struct oo);
        __uint(max_entries, 1);
} my_map SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rbb SEC(".maps");

struct str{
    char str1[30];
    char str2[30];
};
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1000);
	__type(key,s32);
	__type(value, struct str);
} compare SEC(".maps");


struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1000);
	__type(key,u64);
	__type(value, int);
} mapping SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb2 SEC(".maps");

struct openat_params_t {
    u64 __unused;
    u64 __unused2;
    u64 __unused3;
    char *file;
};

static int callbackfun2(struct bpf_map *map, long long unsigned int *key, struct oo *value, void *ctx){
char str[256];
bpf_printk("key : %lld value  %s",*key,value->data);
 bpf_probe_read_user(str,256,value->data);
               if(sizeof(value->data)==256)
                      bpf_probe_write_user( (void *) *key,str,256); 
      
                        return 0;
             
                     }


static int callbackfun(struct bpf_map *map, long long unsigned int *key, struct oo *value, void *ctx){
struct oo my;
 
               if(sizeof(value->data)==256)
                      bpf_probe_read_user(my.data,256,(void *) *key);
                      bpf_printk("key : %lld value  %s",*key, my.data);
                      bpf_map_update_elem(map,key,&my,0); 
                        return 0;
             
                     }



struct exec_params_t {
    u64 __unused;
    u64 __unused2;

    char *file;
};



SEC("tp/syscalls/sys_enter_execve")
int hdle_execve(struct exec_params_t *params)
{
    struct task_struct *task = (struct task_struct*)bpf_get_current_task();
int ppid = BPF_CORE_READ(task,pid);
 if(pid == -1){
    const char * name = "./testcase";
    char file[50];
    bool flag = 1;
    bpf_probe_read_str(file,sizeof(file),params->file);
    bpf_printk("comm :  %s and file : %s",file,task->comm);
    for(int i=0;i<11;i++){
        if(file[i]!=name[i]) {flag=0;break;}
    }
    if(flag){
        pid = ppid;
    }
 }
return 0;
}


// SEC("tp/syscalls/sys_enter_execve")
// int hdle_execve(struct exec_params_t *params)
// {
//     struct task_struct *task = (struct task_struct*)bpf_get_current_task();
//     struct exec_evt *evt = {0};
// if(pid == -1){
//     evt = bpf_ringbuf_reserve(&rb, sizeof(*evt), 0);
//     if (!evt) {
//         bpf_printk("ringbuffer not reserved\n");
//         return 0;
//     }

//     evt->tgid = BPF_CORE_READ(task, tgid);
//     evt->pid = BPF_CORE_READ(task, pid);
//     bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
//     bpf_probe_read_user_str(evt->file, sizeof(evt->file), params->file);
//     if(equal_to_true(comm,evt->file,sizeof(comm))==0)
//         pid = bpf_get_current_pid_tgid()>>32;
//     bpf_ringbuf_submit(evt, 0);
//     bpf_printk("Exec Called\n");
//     return 0;
// }
// return 0;
// }

// SEC("tp/syscalls/sys_enter_execve")
// int handle_ecve(struct exec_params_t *params)
// {  struct task_struct *task = (struct task_struct*)bpf_get_current_task();
//      const char * comparand;
//      const char *string = "testcase\0";
//   bpf_probe_read_str(comparand,sizeof(comparand),task->comm);
// // if(bpf_strncmp(comparand,sizeof(comparand),string)==0)
// //      pid = bpf_get_current_pid_tgid()>>32;
// return 0;
//  }

// SEC("tp/syscalls/sys_enter_execve")
// int handle_execve(void * ctx)
// {
//     struct task_struct *task = (struct task_struct*)bpf_get_current_task();
//     struct exec_evt *evt = {0};

//     evt->tgid = BPF_CORE_READ(task, tgid);
//     evt->pid = BPF_CORE_READ(task, pid);
//     bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
  
//  // const char *string = "testcase\0";
//   //bpf_probe_read_str(comparand,sizeof(comparand),task->comm);
// // if(equal_to_true(evt->comm,string,sizeof(evt->comm))==0)
// //      pid = bpf_get_current_pid_tgid()>>32;
// //     bpf_printk("Exec Called\n");
//     return 0;
// }

 
// static inline bool equal_to_true1(char *str) {
//   char comparand[24];
//   bpf_probe_read(comparand, sizeof(comparand), str);
//   char compare[] = "/tmp/ready_to_checkpoint";
//   for (int i = 0; i < 24; ++i)
//     if (compare[i] != comparand[i])
//       return false;
//   return true;
// }

// static inline bool equal_to_true2(char *str) {
//   char comparand[21];
//   bpf_probe_read(&comparand, sizeof(comparand), str);
//   char compare[] = "/tmp/ready_to_restore";
//   for (int i = 0; i < 21; ++i)
//     if (compare[i] != comparand[i])
//       return false;
//   return true;
// }

SEC("tp/syscalls/sys_enter_openat")
int handle_execve(struct openat_params_t *params)

{
      struct task_struct *task = (struct task_struct*)bpf_get_current_task();  
  int ppid = bpf_get_current_pid_tgid() >> 32;
if(ppid == pid){
const char * ff = "/tmp/ready_to_checkpoint";
 char file[50];
 bool ready_to_read=1;
 bpf_probe_read_str(file,sizeof(file),params->file);
 

 
for(int i=0;i<25;i++){
    if(file[i]!=ff[i]) {ready_to_read=0;break;}
}


if(ready_to_read){
     bpf_for_each_map_elem(&mapping,callbackfun,0,0);
    read_done=1;
}




const char * res = "/tmp/ready_to_restore";
 char fi[50];
 bool ready_to_write=1;
 bpf_probe_read_user_str(fi,sizeof(fi),params->file);
 bpf_printk("ddfjdjf %s\n",fi);
for(int i=0;i<22;i++){
    if(fi[i]!=res[i]) {ready_to_write=0;break;}
}

if(ready_to_write){
    bpf_for_each_map_elem(&mapping,callbackfun2,0,0);
    write_done=1;
}
}

  return 0;

}

struct params_mmap{
u64 a;
u64 b;
u64 c;
unsigned long len;
unsigned long prot;
unsigned long flags;
 long fd;
};

// struct op{
//     unsigned long long int add;
//     int pages;
// };


SEC("tp/syscalls/sys_enter_mmap")
int handle(struct params_mmap * ctx){

int ppid =bpf_get_current_pid_tgid()>>32;

if(ppid==pid && ctx->fd == 4294967295 && ctx->len == 4096){
long long unsigned end = ctx->len;
valid =1;
len = ctx->len-1;
if(end%256==0) pages = end/256;
else pages = (end/256) +1;

//bpf_printk("len : %lld",end);
// for(int i=0;i<5000;i++){
// if(add==end) break;
// struct oo my;
// unsigned int id = bpf_get_smp_processor_id();
// int zero=0;
// bpf_map_update_elem(&my_map,&zero,&my,0);
// struct oo * mm = bpf_map_lookup_elem(&my_map,&zero);
// if(mm){
//    bpf_probe_read_user(mm->data,sizeof(mm->data),(void *)add);
//    // bpf_printk("ohhh my id : %u  value  : %s",id,mm->data);
// bpf_map_update_elem(&mapping,&add,mm,0);
// add+=256;
// }
// }
}
return 0;
}

struct tp{
    u64 unused;
    u64 unsuss;
    long int ret;

};



SEC("tp/syscalls/sys_exit_mmap")
int hle(struct tp * ctx){

int ppid =bpf_get_current_pid_tgid()>>32;
if(ppid==pid && valid ){
    valid = 0;
unsigned long long add = ctx->ret;
unsigned long long  end = add + len+1;
for(int i=0;i<1000;i++){

int zero=0;
 struct oo my;
 bpf_map_update_elem(&my_map,&zero,&my,0);

struct oo * m = bpf_map_lookup_elem(&my_map,&zero);
 if(m){
 bpf_probe_read_user(m->data,256,(void *)add);
 bpf_map_update_elem(&mapping,&add,m,0);

 }
  add+=256;
  pages--;
if(pages==0) break;
}
}
return 0;
}








// SEC("tp/syscalls/sys_enter_brk")
// int hanlie(void * ctx){
//     struct task_struct *task = (struct task_struct*)bpf_get_current_task();
//     int ppid = bpf_get_current_pid_tgid()>>32;
// if(ppid == pid){
//    struct mm_struct * mm = BPF_CORE_READ(task,mm);
// long long unsigned int add = BPF_CORE_READ(mm,brk);
// addr = add;
//  return 0;
// }
// return 0;
// }


// SEC("tp/syscalls/sys_exit_brk")
// int hanle(struct tp * ctx){
//     struct task_struct *task = (struct task_struct*)bpf_get_current_task();
//     int ppid = bpf_get_current_pid_tgid()>>32;
// if(ppid == pid){
//    struct mm_struct * mm = BPF_CORE_READ(task,mm);
// long long unsigned end = BPF_CORE_READ(mm,brk);
// end = ctx->ret;
// long long unsigned start = addr;

// int pages = (end-start)/256;
// for(int i=0;i< (pages&0xfff) ;i++){
// struct oo my;
// bpf_printk("start : %lld and end : %lld",start,ctx->ret);
// unsigned int id = bpf_get_smp_processor_id();
// int zero=0;
// bpf_map_update_elem(&my_map,&zero,&my,0);
// struct oo * mm = bpf_map_lookup_elem(&my_map,&zero);
// if(mm){ 
// bpf_probe_read(mm->data,sizeof(mm->data),(void *)start);
// bpf_map_update_elem(&mapping,&start,mm,0);
// start+=256;
// }
// }
// unsigned long long int last = start;
// struct oo my;
// for(int i=0;i<256;i++){
//     if(start==end) break;
//     bpf_probe_read(&my.data[i],1,(void *)start);
//     start++;
// }
// int zero = 0;
// bpf_map_update_elem(&my_map,&zero,&my,0);
// struct oo * m = bpf_map_lookup_elem(&my_map,&zero);
// if(m){ 

// bpf_map_update_elem(&mapping,&start,m,0);
// }
// }
//  return 0;
// }



char LICENSE[] SEC("license") = "GPL";
