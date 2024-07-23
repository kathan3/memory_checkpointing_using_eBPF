#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <string.h>
#include "exec.h"
#include <stdio.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include "exec.skel.h"



static void bump_memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur	= RLIM_INFINITY,
		.rlim_max	= RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
		fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
		exit(1);
	}
}

static int handle_evt(void *ctx, void *data, size_t sz)
{
    const struct exec_evt *evt = data;

    fprintf(stdout, "tgid: %d <> pid: %d -- comm: %s <> file: %s\n", evt->tgid, evt->pid, evt->comm, evt->file);

    return 0;
}





int main(void)
{
      
    bump_memlock_rlimit();
struct exec * skel = exec__open();
    exec__load(skel);
    exec__attach(skel);

    
   fprintf(stdout,"%d ",skel->data->pid);
    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_evt, NULL, NULL);
   while(!skel->bss->read_done){
    ring_buffer__poll(rb,1000);
   }

   FILE * f ;
   fflush(f);
   f = fopen("/tmp/checkpoint_complete","w");
fclose(f);

while(!skel->bss->write_done){
}

   FILE * fl ;
   fflush(fl);
   fl = fopen("/tmp/restore_complete","w");
fclose(fl);


// while(1){

// if(skel->bss->write_done) break;
// }

// FILE * ff= fopen("/tmp/restore_complete","w");
// fclose(ff);

// int bytes_read;
//    while ((bytes_read = fread(data,1,4096,ff)) > 0) {
// skel1->bss->maqsad=0;
//         // Process the buffer (example: print it)
//      //  printf("Read %zu bytes:\n", bytes_read);
//     if(vm_start[ii]==vm_endd[ii]){
//         ii++;
//     }
// printf("sdfsfdsf \n");
//          for (size_t i = 0; i < bytes_read; i++) {
//             printf("%02x",data[i]);
// //printf("%c",data[i]);
//              // Print each byte in hexadecimal format
//         }
//     //    skel1->bss->vma_start=vm_start[ii];
//       //  skel1->bss->maqsad=1;
//        // sleep(1);
//     //   printf("\nvma start : %lld and vma-end : %lld\n",vm_start[ii],vm_endd[ii]);
//         vm_start[ii]+=4096;
//     }
  


//  printf("dddd");

 



//     while (fscanf(file, "%s %s %s", &col,&column2, &column3) == 3) {
//         // Print or use the values of the 2nd and 3rd columns
//        printf("Column 2: %s, Column 3: %s\n", column2, column3);
    
//         long int vma_start = strtol(column2, NULL, 16);
//         long int vma_end = strtol(column3, NULL, 16);
//         printf("start : %ld  end : %ld\n",vma_start,vma_end);
// while(vma_start!=vma_end){
//          if(vma_end-vma_start>4096){
//          skel1->bss->vma_start = vma_start;
//          skel1->bss->vma_end = vma_end;
//         // ring_buffer__poll(rb2,1000); 
//         vma_start+=4096;
//          }
       
//  }
//      }


return 0;

}
