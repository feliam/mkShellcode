#include <stdarg.h>


char message[] = "HOLA MUNDO!(shellcode)\n";


/* Linux takes system call arguments in registers:
        syscall number  %eax         call-clobbered
        arg 1           %ebx         call-saved
        arg 2           %ecx         call-clobbered
        arg 3           %edx         call-clobbered
        arg 4           %esi         call-saved
        arg 5           %edi         call-saved
        arg 6           %ebp         call-saved
*/

#if __x86_64__
/* 64-bit */
long syscall(long syscall_number, long arg1, long arg2, long arg3, long arg4, long arg5,  long arg6){
    long ret;
    asm volatile (
        "movq %1, %%rax\n\t"
        "movq %2, %%rdi\n\t"
        "movq %3, %%rsi\n\t"
        "movq %4, %%rdx\n\t"
        "movq %5, %%rcx\n\t"
        "movq %6, %%r8\n\t"
        "movq %7, %%r9\n\t"
        "syscall"
        : "=a"(ret)
        : "g"(syscall_number), "g"(arg1), "g"(arg2), "g"(arg3), "g"(arg4), "g"(arg5), "g"(arg6)    );
return ret;
}

 
#else
int syscall(int syscall_number, ... ){
    int ret;
    asm volatile (
        "movl %1, %%eax\n\t"
        "movl %2, %%ebx\n\t"
        "movl %3, %%ecx\n\t"
        "movl %4, %%edx\n\t"
        "movl %5, %%edi\n\t"
        "movl %6, %%esi\n\t"
        "movl %7, %%ebp\n\t"
        "int $0x80"
        : "=a"(ret)
        : "g"(syscall_number), "g"(*(&syscall_number+1)), "g"(*(&syscall_number+2)), "g"(*(&syscall_number+3)), "g"(*(&syscall_number+4)), "g"(*(&syscall_number+5)), "g"(*(&syscall_number+6))
        : "%ebx", "%ecx", "%edx", "%esi", "%edi", "%ebp"
    );
return ret;
}
#endif

int write(long fd, void* buffer, unsigned long size){
    return syscall(1L, fd, buffer, size,0,0,0);
}
int ex1t(int errorlevel){
    return syscall(60, errorlevel,0,0,0,0,0);
}


int shellcode(){
    write(1,message,2300);
    ex1t(0);
    //write(0,"CHAU\n",5);
}


