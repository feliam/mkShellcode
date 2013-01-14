#include <stdio.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <assert.h>

/* Shellcode testbed
 *
 * man mmap:
 *  mmap()  creates a new mapping in the virtual address space of the call-
 *          ing process.  The starting address for the new mapping is specified
 *          in addr.  The length argument specifies the length of the mapping.
 *
 * */
int
main (int argc, char *argv[])
{
    void *p;
    int fd;
    off_t size;

    if (argc != 2)
      {
	  printf ("Usage:\n\t%s shellcode.bin\n", argv[0]);
	  exit (-1);
      }

//Open tha file
    fd= open (argv[1], O_RDONLY);
    assert ( fd != -1);
//Read the size
    size = lseek (fd, 0, SEEK_END);
    lseek (fd, 0, SEEK_SET);
    assert ( size != 0);
//Allocates a virtual memory map RWX
    p = mmap (NULL, size, PROT_EXEC | PROT_READ | PROT_WRITE,
	      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    printf ("Memory@%p\n", p);

//Reads content of the "binary" file into mem
    assert(size == read (fd, p, size));

//Close the file so the shellcode inherits only 0,1,2
    close (fd);

//Call the first instruction in mem
    printf ("Passing control to the shellcode...\n");
    ((void (*)()) p) ();
    printf ("The shellcode has returned to main!\n");
    exit (-1);
}
