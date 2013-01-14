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

int write(int fd, void* buffer, unsigned int size){
    return syscall(4, fd, buffer, size, 0,0,0);
}


int shellcode(){
    write(1,message,23);
    //write(0,"CHAU\n",5);
}


