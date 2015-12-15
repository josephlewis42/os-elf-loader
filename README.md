# os-elf-loader
A basic ELF loader for an embedded operating system.

This isn't functional without the XINU kernel which isn't fully open source as 
far as I can tell, but it should be a good jumping off point.

* `elf.h`/`elf.c` - ELF reader. It also keeps tables of where each function is
stored so it can be resolved later using the program loader
* `load_library.c` - Loads an ELF library.
* `load_program.c` - Loads a program to be executed and links it.
* `elfdump.c` - A tiny debugging program for showing libraries/pointers/functions in ELF files.

For the sake of posterity and understanding the loader, XINU itself is an ELF 
file. So, to get the pointers to the builtin system functions, we load up its image, read the locations of the functions and subtract off the difference between the pointer to the builtin function and the new read one.
