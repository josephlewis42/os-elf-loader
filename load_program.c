/* load_program.c - load_program */

#include <xinu.h>

/*------------------------------------------------------------------------
 *  load_program  -  Dynamically load a program
 *------------------------------------------------------------------------
 */
void*	load_program(
	  char		*path		/* Path to the program 		*/
        )
{
    char* progdata;
    int proglen;
    int fd;
    int rc;
    void* main;

    fd = open(RFILESYS, path, "or");
    if(fd == SYSERR)
    {
        return (void*) SYSERR;
    }

    proglen = control(RFILESYS, RFS_CTL_SIZE, fd, 0);
    if(proglen == SYSERR)
    {
        close(fd);
        return (void*) SYSERR;
    }

    progdata = getmem(proglen);
    if(progdata == (void*) SYSERR)
    {
        close(fd);
        return (void*) SYSERR;
    }

    rc = read(fd, progdata, proglen);
    if(rc < proglen || rc == SYSERR)
    {
        close(fd);
        return (void*) SYSERR;
    }

    //printElf(progdata);
    if(SYSERR == linkFile(progdata))
    {
    	//kprintf("could not link file\n");
    	freemem(progdata, proglen);
    	return (void*) SYSERR;
    }


	main = resolveSymbol(progdata, "main");

	if(main == NULL)
	{
    	//kprintf("no main\n");
		freemem(progdata, proglen);
		return (void*) SYSERR;
	}

    close(fd);

	return main;
}
