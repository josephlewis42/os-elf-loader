#include <xinu.h>


Elf32_Ehdr* elf_header(char* elf_addr){
    return (Elf32_Ehdr*) elf_addr;
}


void printRelocation(Elf32_Rel* rels, int num)
{
    int i;
    Elf32_Rel rel;
    kprintf("Offset\tSymbol\tType\n");

    for(i = 0; i < num; i++)
    {
        rel = rels[i];
        kprintf("%x\t%d\t%d\n", rel.r_offset, ELF32_R_SYM(rel.r_info), ELF32_R_TYPE(rel.r_info));
    }
}

void printSymtab(Elf32_Sym* syms, int num, char* strindex)
{
    int i;
    Elf32_Sym sym;

    kprintf("\n\nFound %d items in symtab:\n", num);

    kprintf("Number\tValue\tSize\tType\tGlobal?\tIndex\tName\n");
    for(i = 0; i < num; i++)
    {
        sym = syms[i];
        kprintf("%d\t%x\t%d\t%d\t%d\t%d\t%s\n", i, sym.st_value, sym.st_size, ELF32_ST_TYPE(sym.st_info), ELF32_ST_BIND(sym.st_info) == STB_GLOBAL,
        sym.st_shndx, &strindex[sym.st_name]);
    }
}

void printElf(char* elf)
{

    Elf32_Ehdr* hdr = elf_header(elf);
    Elf32_Shdr* shdr = (Elf32_Shdr*) &elf[hdr->e_shoff];
    Elf32_Shdr sh;
    char* strindex;
    char* strtabindex;
    int i;

    kprintf("ELF DIAGNOSTICS\n");
    kprintf("\n\n");

    kprintf("Header:\n");
    kprintf("\ttype %d\n", hdr->e_type);
    kprintf("\tmachine %d\n", hdr->e_machine);
    kprintf("\tversion 0x%x\n", hdr->e_version);
    kprintf("\tentry 0x%x\n", hdr->e_entry);
    kprintf("\tphoff 0x%x\n", hdr->e_phoff);
    kprintf("\tshoff 0x%x\n", hdr->e_shoff);
    kprintf("\theader size %d\n", hdr->e_ehsize);
    kprintf("\tphentsize %d\n", hdr->e_phentsize);
    kprintf("\tph num %d\n", hdr->e_phnum);
    kprintf("\tshent size %d\n", hdr->e_shentsize);
    kprintf("\tsh num %d\n", hdr->e_shnum);
    kprintf("\tsh str index %d\n", hdr->e_shstrndx);
    kprintf("\tsh str index offset %d\n", shdr[hdr->e_shstrndx].sh_offset);
    kprintf("\n\n");
    /**
    strindex = &elf[shdr[hdr->e_shstrndx].sh_offset];
    strtabindex = strindex; // set this to be semi-safe

    kprintf("Section Headers (%d)\n", hdr->e_shnum);

    kprintf("[NR]\t\t\tName\tType\tAddr\tOff\tSize\tFlags\n");
    for(i = 0; i < hdr->e_shnum; i++)
    {
        sh = shdr[i];
        kprintf("[%d]\t%20s\t%d\t%x\t%x\t%x\t%x\n", i,&strindex[sh.sh_name], sh.sh_type, sh.sh_addr, sh.sh_offset, sh.sh_size, sh.sh_flags);

        if(sh.sh_type == SHT_STRTAB && i != hdr->e_shstrndx)
        {
            kprintf("* found alloc table\n");
            strtabindex = &elf[sh.sh_offset];
        }
    }

    kprintf("\n");

    for(i = 0; i < hdr->e_shnum; i++)
    {
        sh = shdr[i];
        if(sh.sh_type == SHT_SYMTAB)
        {
            printSymtab((Elf32_Sym*) &elf[sh.sh_offset], sh.sh_size / sizeof(Elf32_Sym), strtabindex);
        }

        if(sh.sh_type == SHT_REL)
        {
            printRelocation((Elf32_Rel*) &elf[sh.sh_offset], sh.sh_size / sizeof(Elf32_Rel));
        }
    }**/
}


/*------------------------------------------------------------------------
 * main  -  Main function
 *------------------------------------------------------------------------
 */
int	main (
	int	argc,	/* Number of arguments	*/
	char	*argv[]	/* Arguments array	*/
	)
{

    char* progdata;
    int proglen;
    int fd;
    int rc;
    void* main;

    if(argc < 2)
    {
        printf("Usage: %s file\n", argv[0]);
        return 1;
    }


    fd = open(RFILESYS, argv[1], "or");
    if(fd == SYSERR)
    {
        return SYSERR;
    }

    proglen = control(RFILESYS, RFS_CTL_SIZE, fd, 0);
    if(proglen == SYSERR)
    {
        close(fd);
        return SYSERR;
    }

    progdata = getmem(proglen);
    if(progdata == (void*) SYSERR)
    {
        close(fd);
        return  SYSERR;
    }

    rc = read(fd, progdata, proglen);
    if(rc < proglen || rc == SYSERR)
    {
        close(fd);
        return SYSERR;
    }

    printElf(progdata);
    freemem(progdata, proglen);

    close(fd);

	return 0;
}

