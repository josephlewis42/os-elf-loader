#define __xinu__
#ifndef __xinu__
#include "../include/elf.h"
#include <stdio.h>
#define kprintf printf
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

#else
#include <xinu.h>
#endif

#define ADDR_PLUS_BYTES(addr, nbytes) ( (void*) &((char*)addr)[nbytes] )


Elf elftab[NUM_ELF_LIBS_SUPPORTED];


void init_elf_system()
{
	int symdiff;
	int i, j;
	for(i = 0; i < NUM_ELF_LIBS_SUPPORTED; i++)
	{
		elftab[i].used = FALSE;
		for(j = 0; j < NUM_SYMS_PER_ELF; j++)
		{
			elftab[i].symbols[j].symptr = NULL;
		}
	}

	// setup XINU
	if(SYSERR == load_library("xinu.elf"))
	{
		panic("Could not load xinu's symbols");
	}


	// fix all the offsets to be the real xinu ones
	// TODO see if this works!


	symdiff = (int)find_library_function("load_program") - (int) load_program;

	for(i = 0; i < NUM_ELF_LIBS_SUPPORTED; i++)
	{
		if(elftab[i].used == FALSE)
			continue;

		for(j = 0; j < NUM_SYMS_PER_ELF; j++)
		{
			if(elftab[i].symbols[j].symptr != NULL)
				elftab[i].symbols[j].symptr = ADDR_PLUS_BYTES(elftab[i].symbols[j].symptr, -symdiff);
		}
	}
}


Elf32_Ehdr* elf_header(char* elf_addr){
    return (Elf32_Ehdr*) elf_addr;
}


typedef struct {
    Elf32_Shdr* header; // the pointer to the first section header
    int n_headers; // the number of headers
    char* header_strs; // pointer to the header strings table
} sectioninfo;

sectioninfo elf_section_header(char* elf_addr){
    sectioninfo info;
    Elf32_Ehdr* hdr = elf_header(elf_addr);

    info.header = (Elf32_Shdr*) &elf_addr[hdr->e_shoff];
    info.n_headers = hdr->e_shnum;
    info.header_strs = &elf_addr[info.header[hdr->e_shstrndx].sh_offset];
    return info;
}


char* elf_section_strtab(char* elf_addr){
    int i;
    Elf32_Ehdr* hdr = elf_header(elf_addr);
    sectioninfo sinfo = elf_section_header(elf_addr);
    Elf32_Shdr sh;

    for(i = 0; i < sinfo.n_headers; i++)
    {
        sh = sinfo.header[i];
        if(sh.sh_type == SHT_STRTAB && i != hdr->e_shstrndx)
        {
            return &elf_addr[sh.sh_offset];
        }
    }

    return (char*) 0;
}

typedef struct {
    Elf32_Sym* symtab;
    int num;
    char* symstrs;
} syminfo;



// resolves the address of a section name
void* resolveSection(char* elf_addr, char* name){
    int i;
    sectioninfo sinfo = elf_section_header(elf_addr);
    Elf32_Shdr sh;

    for(i = 0; i < sinfo.n_headers; i++)
    {
        sh = sinfo.header[i];

        if(streq(&sinfo.header_strs[sh.sh_name], name))
        {
            return ADDR_PLUS_BYTES(elf_addr, sh.sh_offset);
        }
    }

    return (void*) 0;
}

void* resolveSectionNum(char* elf_addr, int num){
    sectioninfo sinfo = elf_section_header(elf_addr);
    Elf32_Shdr sh;

    if(num >= sinfo.n_headers)
    {
        return (void*) 0;
    }

    sh = sinfo.header[num];
    return ADDR_PLUS_BYTES(elf_addr, sh.sh_offset);
}



syminfo elf_symtab(char* elf_addr)
{
    syminfo tofill;
    sectioninfo sinfo = elf_section_header(elf_addr);
    Elf32_Shdr sh;
    int i;

    for(i = 0; i < sinfo.n_headers; i++)
    {
        sh = sinfo.header[i];
        if(sh.sh_type == SHT_SYMTAB)
        {
            tofill.num = sh.sh_size / sizeof(Elf32_Sym);
            tofill.symtab = (Elf32_Sym*) &elf_addr[sh.sh_offset];
            tofill.symstrs = (char*) resolveSection(elf_addr, ".strtab");

            return tofill;
        }
    }

    tofill.num = 0;
    tofill.symtab = (Elf32_Sym*) 0;
    tofill.symstrs = (char*) 0;

    return tofill;
}


int _strlen(char* a){  // to cross compile on linux & xinu
    int i = 0;

    while( a[i] != '\0' )
        i++;

    return i;
}

int streq(char* a, char* b) { // to cross compile on linux & xinu
    int i;

    if(_strlen(a) != _strlen(b))
        return 0;

    for(i = 0; i < _strlen(a); i++)
        if(a[i] != b[i])
            return 0;

    return 1;
}


// resolves a name in the file, returns NULL on no resolution
void* resolveSymbol(char* elf_addr, char* name){
    int i;
    Elf32_Sym sym;
    syminfo syminf = elf_symtab(elf_addr);

    for(i = 0; i < syminf.num; i++)
    {
        sym = syminf.symtab[i];

        if(ELF32_ST_BIND(sym.st_info) != STB_GLOBAL) // skip non exported funcs
            continue;

        if(ELF32_ST_TYPE(sym.st_info) != STT_FUNC) // skip non-funcs
            continue;

        if(streq(name, &syminf.symstrs[sym.st_name]))
            return (void*) &((char*) resolveSection(elf_addr, ".text"))[sym.st_value];
    }

    return (void*) 0;
}

// gives the address for this symbol entry or 0 for null
void* resolve_symbol_entry(char* elf_addr, int entry){
    syminfo syminf = elf_symtab(elf_addr);
    Elf32_Sym sym;

    if(entry == SHN_UNDEF)
    {
        return 0;
    }

    if(entry >= syminf.num)
    {
        //kprintf("symbol entry too high %d\n", entry);
        return (void*) SYSERR;
    }


    sym = syminf.symtab[entry];

    // absolute value symbols
    if(SHN_ABS == sym.st_shndx)
    {
        return (void*) sym.st_value;
    }

    // undefined symbols, try library lookup.
    if(SHN_UNDEF == sym.st_shndx)
    {
        return find_library_function(&syminf.symstrs[sym.st_name]);
    }

    // all others (should be sections)
    return ADDR_PLUS_BYTES(resolveSectionNum(elf_addr, sym.st_shndx), sym.st_value);
}

// sets up the bss segment for the file, syserr if there is no memory to do
// it in
syscall setup_bss(char* elf_addr)
{
    sectioninfo sect_head = elf_section_header(elf_addr);
    int i, j;
    Elf32_Shdr* section;

    // look for bss sections.
    for(i = 0; i < sect_head.n_headers; i++)
    {
        section = &sect_head.header[i];

        // this is a BSS section.
        if(section->sh_type == SHT_NOBITS)
        {
            // ignore if we don't want to allocate anything
            if(section->sh_size == 0)
            {
                continue;
            }

            //kprintf("Creating BSS of size: %x\n", section->sh_size);

            // We need to allocate this bss segment.
            if(section->sh_flags & SHF_ALLOC)
            {
                char* bss = getmem(section->sh_size);

                if(bss == (char*) SYSERR)
                {
                    return SYSERR;
                }

                for(j = 0; j < section->sh_size; j++)
                {
                    bss[j] = 0;
                }

                section->sh_offset = (int32) bss - (int32) elf_addr;
            }
        }
    }

    return OK;
}

syscall elf_handle_rel_entry(char* elf_addr, Elf32_Rel rel, Elf32_Shdr sh)
{
    int a = (int) resolveSectionNum(elf_addr, sh.sh_info);
    int* referenced_sect_addr = (int*) (a + rel.r_offset);

    unsigned char rtype = ELF32_R_TYPE(rel.r_info);
    // should be equal to shdr - 1 hdr by the way gcc spits things out it seems.

	// Symbol value
	int symval = (int) resolve_symbol_entry(elf_addr, ELF32_R_SYM(rel.r_info));

	if(SYSERR == symval)
	{
	    return SYSERR;
	}

	//kprintf("Got symbol value for %x to be: %x\n", referenced_sect_addr, symval);
	if(R_386_NONE == rtype)
	{
	    return OK;
	}

	if(R_386_32 == rtype)
	{
		*referenced_sect_addr = symval + *referenced_sect_addr;
		return OK;
	}

	if(R_386_PC32 == rtype)
	{
		*referenced_sect_addr = (symval + *referenced_sect_addr - (int)referenced_sect_addr);
		return OK;
	}

	return SYSERR;

}


syscall elf_handle_rel_sect(char* elf_addr, Elf32_Rel* rels, Elf32_Shdr sh)
{
    int num_rels = sh.sh_size / sizeof(Elf32_Rel);
    int i;

    for(i = 0; i < num_rels; i++)
    {
        if(elf_handle_rel_entry(elf_addr, rels[i], sh) == SYSERR)
        {
            return SYSERR;
        }
    }

    return OK;
}


syscall linkFile(char* elf_addr)
{
    int i;
    Elf32_Rel* rels;
    sectioninfo sinfo = elf_section_header(elf_addr);
    Elf32_Shdr sh;

    // setup BSS
    if(setup_bss(elf_addr) == SYSERR)
    {
        return SYSERR;
    }

    // setup links in the rest of the file and out to libraries.

    for(i = 0; i < sinfo.n_headers; i++)
    {
        sh = sinfo.header[i];
        if(sh.sh_type != SHT_REL)
        {
           continue;
        }

        rels = (Elf32_Rel*) ADDR_PLUS_BYTES(elf_addr, sh.sh_offset);

        // a relocatable bit
        if(elf_handle_rel_sect(elf_addr, rels, sh) == SYSERR)
        {
            return SYSERR;
        }
    }

    return OK;
}


syscall loadSyms(char* elf_addr, Elf* elf_entry)
{
	int symindex = 0; // index of the last symbol in the table

    int i;
    Elf32_Sym sym;
    syminfo syminf = elf_symtab(elf_addr);

    for(i = 0; i < syminf.num; i++)
    {
        sym = syminf.symtab[i];

        if(ELF32_ST_BIND(sym.st_info) != STB_GLOBAL) // skip non exported funcs
            continue;

        if(ELF32_ST_TYPE(sym.st_info) != STT_FUNC && ELF32_ST_TYPE(sym.st_info) != STT_OBJECT) // skip non-funcs and non-objs
            continue;

        if(find_library_function(&syminf.symstrs[sym.st_name]) != (void*) SYSERR)
        {
        	return SYSERR;
        }

		elf_entry->symbols[symindex].symname = &syminf.symstrs[sym.st_name];
		elf_entry->symbols[symindex].symptr = (void*) &((char*) resolveSection(elf_addr, ".text"))[sym.st_value];
		symindex++;
    }

    return OK;
}

