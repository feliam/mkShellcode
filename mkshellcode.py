from StringIO import StringIO
from elftools.elf.elffile import ELFFile,RelocationSection,SymbolTableSection
from elftools.elf.enums import ENUM_RELOC_TYPE_i386, ENUM_RELOC_TYPE_x64
import sys,struct,subprocess
def run(cmd):
    return subprocess.check_output(cmd.split(' '))

def find_relocations_for_section(elf, section_name):
    """ Given a section, find the relocation section for it in the ELF
        file. Return a RelocationSection object, or None if none was
        found.
    """
    rels = elf.get_section_by_name(b'.rel' + section_name)
    if rels is None:
        rels = elf.get_section_by_name(b'.rela' + section_name)
    return rels

#the user shellcode
filename = sys.argv[1]

#read the ELF object file
elf = ELFFile(file(filename)) 

#64 bit not implemented!
print('[II] Object %s is a %s_%s elf' % (filename, elf.get_machine_arch(), elf.elfclass))
assert elf.elfclass == 32 and elf.get_machine_arch() == 'x86'

#assemble and load loader .text section
run('as -32 loader_x86.s -o loader.o')  #32 bit only
loader  = ELFFile(file('loader.o')).get_section_by_name('.text').data()
print "[II] %s loader is %d bytes long"%(elf.get_machine_arch(),len(loader))


#list of elf sections
print "[II] Elf has %d sections."% elf.num_sections()

#Select the interesting sections...
selected_sections = [".text",".data", ".bss"]
for section in elf.iter_sections():
  if section.name.startswith(".rodata"):
    selected_sections.append(section.name)

print "[II] Selected sections are: ", " ".join(selected_sections)

#Precalculate the offsets and packs the shellcode
#[text][data][rodata1][rodata2][rodata3]
offsets = {}
shellcode = StringIO('')
for section_name in selected_sections:
    offsets[section_name] = shellcode.len
    try:
        data = elf.get_section_by_name(section_name).data()
        print "[II] Section %s is %d bytes offset %d"%(section_name,len(data),offsets[section_name])
    except:
        data = ''
        print '[WW] No %s section'%section_name
    shellcode.write(data)

print "[II] Total packed data size %d" % shellcode.len

#FIX RELOCS!
relocs = []
for section_name in selected_sections:
    reloc_section = find_relocations_for_section(elf, section_name)
    if reloc_section is None:
        continue
    symtab = elf.get_section(reloc_section['sh_link'])
    for reloc in reloc_section.iter_relocations():
        assert elf.get_machine_arch() == 'x86' and not reloc.is_RELA()
        reloc_base = offsets[section_name]
        reloc_offset = reloc['r_offset']
        reloc_type = reloc['r_info_type']
        target_symbol = symtab.get_symbol(reloc['r_info_sym'])
        target_name = elf.get_section(target_symbol['st_shndx']).name
        target_base = offsets[target_name]
        target_offset = target_symbol['st_value']

        shellcode.seek(reloc_base+reloc_offset)
        value = struct.unpack("<l",shellcode.read(4))[0]
        print "RELOC:",section_name, reloc_base, reloc_offset, "=>", target_name, target_base,target_offset, value
        if reloc_type == ENUM_RELOC_TYPE_i386['R_386_32']:
            value = target_base + target_offset + value
            relocs.append(reloc_base+reloc_offset)
            print "[II] Offset ",reloc_base+reloc_offset, "added to reloc list"
        elif reloc_type == ENUM_RELOC_TYPE_i386['R_386_PC32']: #relative reference to text
            value = (target_base + target_offset) -  (reloc_base + reloc_offset) + value 
        else:
            assert reloc_type == ENUM_RELOC_TYPE_i386['R_386_NONE']
        shellcode.seek(reloc_base + reloc_offset)
        shellcode.write(struct.pack("<L",value&0xffffffff))
    shellcode.seek(shellcode.len)


#addding relocations
print "[II] Adding %d active relocations" % len(relocs)
relocs_data = struct.pack("<L", len(relocs))
for rel in relocs:
    relocs_data += struct.pack("<L", rel)

#Finding entry point
try:
   start, = [s['st_value'] for s in elf.get_section_by_name('.symtab').iter_symbols() if s.name == 'shellcode']
except:
   print "[EE] You must define a shellcode() main function"
   exit(-1)
relocs_data += struct.pack("<L", start)


#The loader is the first chunk of the shellcode
shellcode = loader + relocs_data + shellcode.getvalue()


print "[II] Shellcode len is %d"%len(shellcode)
print "[II] Writing result to %s"%sys.argv[2]
file(sys.argv[2],"wb").write(shellcode)

