all: test32 test64 shellcode.bin

%.o : %.c
	gcc -m32 -march=i386 -fno-stack-protector -fno-common  -Os -fomit-frame-pointer -fno-PIC -c -static $<

%.bin : %.o
	python mkshellcode.py $< $@
test32: test.c
	gcc -m32 test.c -o test32

test64: test.c
	gcc -m64 test.c -o test64

clean:
	rm -f *.o shellcode.bin test32  test64
