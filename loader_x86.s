.section .text
    #esp shall point to writeable memory
    jmp labelA
dummy:
    jmp begin
labelA:
    call dummy
begin:
    #read eip into esi
    popl %esi
    subl $(begin-relocs), %esi
    #leal (%esi), %esi

    #esi points to relocs 
    movl (%esi), %ecx           #Number of relocations
    leal 8(%esi,%ecx,4), %edi   #Start of .text [SIZE|RELOC1|RELOC2|....|RELOCN][START][CODE]
    andl %ecx,%ecx
    jz done
fix_reloc:
    movl (%esi,%ecx,4), %eax
    addl %edi, (%edi,%eax,1)
    dec %ecx
    jne fix_reloc
done:
    addl -4(%edi), %edi
    jmp *%edi
relocs:

