## Buffer overflow

- **Buffer overflow**: a vulnerability that occurs when a program writes more data to the stack than it is allocated to hold. This excess data will **overwrite adjacent memory space**, leading to the corruption of valid data, control flow disruption, and potentially the execution of malicious code.

- Plugin per GDB: **pwndbg** o **GEF** (https://github.com/hugsy/gef)  

- Quando si va in buffer overflow, si ha **Segmentation fault** come errore. Il buffer overflow è pericoloso quando si arriva a sovrascrivere specifiche parti di memoria.
- Si potrebbe scrivere uno *shell code* (*execve*) sulla memoria per leggere file sul file system o ls.

- Sezioni di memoria di un programma in esecuzione:

	- *.text*: area di memoria eseguibile. Contiene il codice eseguibile del programma, ossia le istruzioni macchina. È solitamente di sola lettura per prevenire modifiche accidentali o attacchi.

	- *.data*: contiene variabili globali e statiche **inizializzate** con valori specifici

	- *.rodata*: area di memoria di sola lettura. Contiene dati costanti, come stringhe letterali o valori definiti `const` (stringhe in printf vanno qui)

	- *.bss* (*Block Started by Symbol*): area di memoria leggibile ed eseguibile. Contiene variabili globali e statiche **non inizializzate** o inizializzate a zero (array vuoto va qui)

	- *heap*: contiene memoria allocata dinamicamente durante l'esecuzione tramite funzioni come `malloc`, `calloc`, o `new`

	- *stack*: utilizzata per memorizzare dati temporanei come variabili locali, indirizzi di ritorno delle funzioni, parametri delle funzioni. La dimensione è limitata e un uso eccessivo può causare un **stack overflow**.

### Stack overflow

1. Compiliamo il programma 32-bit:

```bash
gcc -m32 -o vuln vuln.c
```

2. Eseguiamo il programma appena compilato in questo modo:

```bash
vuln stringa_molto_lunga
```

   - *stringa_molto_lunga* dovrebbe accettare al più (circa) 64 caratteri. Nel caso in cui si inserisce una stringa da 100 caratteri, si va in errore (Segmentation fault). Abbiamo sovrascritto parte dello stack.  

3. Analizziamo il programma appena eseguito:

```bash
checksec --file=vuln
```

- **checksec**: comando utilizzato per analizzare un file binario e verificare se sono state abilitate determinate misure di sicurezza durante la compilazione o il linking.

4. Per eseguire uno stack overflow semplice, disattiviamo le opzioni di sicurezza **Canary**, **NX (No Executable)** e **PIE**:

```bash
gcc -m32 -z execstack -no-pie -fno-stack-protector
```

   - *-z execstack*: abilita l'esecuzione di codice dallo stack. In pratica disattiva opzione di sicurezza NX.

   - *-no-pie*: elimina PIE (*Position Independent Executable*), cioè DEP (*Data Execution Prevention*) e **ASLR** (*Address Space Layout Randomization*) randomizzazione degli indirizzi (a livello binario). La randomizzazione deve anche essere disattivata a livello di sistema operativo.

   - *-fno-stack-protector*: elimina *Canary*.

5. Adesso si può rieseguire **checksec** per verificare che le opzioni di sicurezza sono state disattivate.

6. Con gdb (gef) possiamo capire dove va in errore (buffer overflow) il programma:

- *info functions*: comando di gef che restituisce una serie di funzioni (tra cui quella vulnerabile al buffer overflow)

- Il buffer overflow arriva al return, perchè sovrascrivendo la cella di memoria con il valore di ritorno della funzione, il programma non saprà più a che punto dovrà ritornare (e terminare)

- *si*: per muoversi di uno step in avanti in gdb

7. Inviando una stringa molto lunga del tipo AA...AABBBB riusciamo a capire qual è l'ultimo indirizzo di memoria eseguibile (su cui dobbiamo inserire lo shell code). **Nota**: ogni indirizzo di memoria è 32bit in little-endian!
 
- Per verificare la randomizzazione degli indirizzi (2 in output per indirizzi randomici):

```bash
cat /proc/sys/kernel/randomize_va_space
```

- Comando per disattivare la randomizzazione:

```bash
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
```

8. Troviamo online e scarichiamo un *execve*, un payload che eseguirà uno shellcode (RCE) quando l'eseguibile malevolo verrà runnato.

9. Per assemblare un file assembly in un object file:

```bash
nasm -f elf32 execve.asm
```

- Linker che genera un eseguibile a partire dall'object file:

 ```bash
ld -m elf_i386 execve.o -o execve
```

-  Per ispezionare le prime 200 celle di memoria dello stack:

```bash
x/200
```

oppure:

```bash
x/200x $esp
```

  questo comando fa visualizzare le prime 200 celle dello stack a partire dal indirizzo **$esp** (*stack pointer*) e in questo caso serve per trovare la cella di memoria in cui è contenuto l'inizio dello shell code. Per trovare l'inizio dello shell code, basta cercare gli indirizzi subito precedenti ai 90909090.

   
10. Per eseguire il file con shell code in gdb:

```bash
run $(python3 file.py)
```


- Nonostante siano state disattivate tutte le opzioni di sicurezza, fuori dal gdb l'attacco non funziona a causa di variabili d'ambiente.