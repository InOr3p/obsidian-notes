
Reference books:
- *No Starch Press* (foundation of information security, IDA Pro Book, Practical Binary Analysis, Practical Malware Analysis)

- https://book.hacktricks.xyz

Linux distro version da usare: **Ubuntu 22.04 LTS**

- Installare libc e run programmi 32-bit in C:

```bash
sudo dpkg --add-architecture i386
sudo apt update

sudo apt install libc6:i386 libncurses5:i386 libstdc++6:i386

sudo apt install gcc-multilib g++-multilib

# per compilare un programma in formato a 32 bit
gcc -m32 -o my_program my_program.c
```

Installare **Terminal Multiplexer**: `sudo apt install tmux`

Installare **Debugger**: `sudo apt install gdb`

`objdump -d <eseguibile>`: per ottenere codice assembly da file exe
`objdump -s -j .rodata <eseguibile>`:  per analizzare memory location *.rodata* di file exe
`strings <eseguibile>`: stampa tutte le stringhe usate dal file exe

In **gdb**:
	**b -> breakpoint**
	**r -> run**
	**c -> continue** (to continue the execution of the program)
	**file** -> to select the file
	**disass main** -> to disassemble the main function
	**set disassembly-flavor intel** -> sets the output syntax to the intel default
	**x/s mem_addr** -> *x* means *examine* and *s* is the format *string*. This command is used to print the content of the specified memory address as a format string

Exercises:
	https://book.rada.re/crackmes/ioli/intro.html