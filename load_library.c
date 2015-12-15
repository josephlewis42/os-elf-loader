/* load_library.c - load_library */

#include <xinu.h>

/*------------------------------------------------------------------------
 *  load_library  -  Dynamically load a library
 *------------------------------------------------------------------------
 */
syscall	load_library(
	  char		*path		/* Path to the library 		*/
        )
{
    char* progdata;
    int proglen;
    int fd;
    int rc;
    int elftabent;
    Elf* elfentry;


    for(elftabent = 0; elftabent < NUM_ELF_LIBS_SUPPORTED; elftabent++)
    {
    	if(elftab[elftabent].used == FALSE)
    	{
    		break;
    	}
    }

    // make sure we don't load too many libraries
    if(elftabent == NUM_ELF_LIBS_SUPPORTED)
    {
    	//kprintf("too many libs\n");
    	return SYSERR;
    }

    fd = open(RFILESYS, path, "or");
    if(fd == SYSERR)
    {
    	//kprintf("couldn't open lib\n");
    	close(fd);
        return SYSERR;
    }

    proglen = control(RFILESYS, RFS_CTL_SIZE, fd, 0);
    if(proglen == SYSERR)
    {
    	//kprintf("couldn't get proglen\n");
    	close(fd);
        return SYSERR;
    }

    progdata = getmem(proglen);
    if(progdata == (void*) SYSERR)
    {
    	//kprintf("couldn't load progdata\n");
    	close(fd);
        return SYSERR;
    }

    rc = read(fd, progdata, proglen);
    if(rc < proglen || rc == SYSERR)
    {
    	//kprintf("couldn't read full program\n");
    	close(fd);
        return SYSERR;
    }


    elfentry = &elftab[elftabent];


    if(loadSyms(progdata, elfentry) == SYSERR)
    {
    	freemem(progdata, proglen);
    	close(fd);
    	//kprintf("duplicate symbol found\n");
    	return SYSERR;
    }

    elfentry->used = TRUE;
    elfentry->location = (void*) progdata;
    elfentry->lengthbytes = proglen;


    elfentry->name = getmem(strlen(path));
    strncpy(elfentry->name, path, strlen(path)); // set the name.

	// debugging
	//elfPrintLibraryFuncs();

	close(fd);

	return OK;
}
