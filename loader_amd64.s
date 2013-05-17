.section .text
    #esp shall point to writeable memory
    jmp labelA
dummy:
    jmp begin
labelA:
    call dummy
begin:
    #read eip into esi
    popq %rsi
    subq $(begin-relocs), %rsi
    #leal (%esi), %esi

    #esi points to relocs 
    movq (%rsi), %rcx           #Number of relocations
    leaq 16(%rsi,%rcx,8), %rdi   #Start of .text [SIZE|RELOC1|RELOC2|....|RELOCN][START][CODE]
    andq %rcx,%rcx
    jz done
fix_reloc:
    movq (%rsi,%rcx,8), %rax
    addq %rdi, (%rdi,%rax,1)
    dec %rcx
    jne fix_reloc
done:
    addq -8(%rdi), %rdi
    jmpq %rdi
relocs:

