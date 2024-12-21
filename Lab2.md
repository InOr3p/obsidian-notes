## Buffer overflow

- **Stack buffer overflow**

  

- Plugin per GDB: **pwndbg** o **GEF** (https://github.com/hugsy/gef)

  

- Quando si va in buffer overflow, si ha **Segmentation fault** come errore. Il buffer overflow è pericoloso quando si arriva a sovrascrivere specifiche parti di memoria.
- Si potrebbe scrivere uno *shell code* (*execve*) sulla memoria per leggere file sul file system o ls.

  

- - .text: area di memoria eseguibile (stringhe vanno qui)

  - .rodata: area di memoria scrivibile e leggibile (stringhe in printf vanno qui)

  - .bss: area di memoria leggibile e eseguibile (array vuoto va qui)

  

- *gcc -m32 -o file.exe file.c*

- *file.exe stringa_molto_lunga*

  

    *stringa_molto_lunga* dovrebbe accettare al più (circa) 64 caratteri.

    Nel caso in cui si inserisce una stringa da 100 caratteri, si va in errore ma non si può fare altro.

  

- *checksec --file=file.exe*

  

    bisogna disattivare le opzioni di sicurezza Canary, NX (No Executable) e PIE.

  

- **gcc -m32 -z execstack -no-pie -fno-stack-protector**

  

    - -z execstack: abilita l'esecuzione di codice che viene copiato sullo stack. In pratica disattiva opzione di sicurezza NX

    - -no-pie: elimina PIE, cioè DEP e randomizzazione degli indirizzi (a livello binario). La randomizzazione deve anche essere disattivata a livello di sistema operativo

    - -fno-stack-protector: elimina *Canary*

  

- dopo si può rieseguire checksec per verificare che le opzioni di sicurezza sono state disattivate

  

- con gdb (gef) possiamo capire dove va in errore (buffer overflow) il programma

  

- info functions: comando di gef che restituisce una serie di funzioni (tra cui quella vulnerabile al buffer overflow)

- Il buffer overflow arriva al return, perchè sovrascrivendo la cella di memoria con il valore di ritorno della funzione, il programma non saprà più a che punto dovrà ritornare (e terminare)

  

- si: per muoversi di uno step in avanti in gdb

  

- inviando una stringa del tipo AA...AABBBB riusciamo a capire qual è l'ultimo indirizzo di memoria eseguibile (su cui dobbiamo inserire la shell code) (ogni indirizzo di memoria è 32bit in little-endian)

  

- cat /proc/sys/kernel/randomize_va_space

  

    per verificare la randomizzazione di indirizzi (2 in output per indirizzi randomici)

  

- comando ?

  

    per disattivare la randomizzazione

  
  

- nasm -f elf32 execve.asm

  

    assemblare un file assembly in un object file

  

- ld -m elf_i386 execve.o -o execve

  

    - linker che genera un eseguibile a partire dall'object file

  

- x/200

  

    ispeziona le prime 200 celle di memoria dello stack (serve per trovare la cella di memoria in cui è contenuto l'inizio dello shell code). Per trovare l'inizio dello shell code, basta cercare gli indirizzi subito precedenti ai 90909090  

  

- run $(python3 file.py)

  

    per eseguire il file con shell code in gdb

  

- nonostante siano state disattivate tutte le opzioni di sicurezza, fuori dal gdb l'attacco non funziona a causa di variabili d'ambiente