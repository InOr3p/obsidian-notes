### Buffer overflow con meccanismi di sicurezza attivi (1)

- **NX**: *Not Executable*, quando attivo disabilita l'esecuzione di *shell code*

- Per riabilitarlo, si elimina *-z execstack*  

- Per verificare il cambiamento degli indirizzi:

 ```bash
 ldd filename.exe | grep libc
 ```


- Per caricare la libc sempre allo stesso indirizzo:

```bash
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
```
  

- Il programma va sempre in **Segmentation fault**. Per risolvere, si può usare la **Ret2libc** (*Return To libc*)  

- Libc ha una serie di indirizzi di base ad offset di memoria prestabiliti:

    - 0x0 -> BASE ADDRESS (visibile con comando `ldd filename.exe | grep libc`)

    - 0x1 -> SYSTEM

    - 0x2 -> READ

    - 0x3 -> WRITE

    - 0x4 -> SETUID

    - 0x5 -> OPEN

    - 0x19 -> bin/sh (argomento della funzione)

- `p system` (in GDB con eseguibile runnato) per trovare l'indirizzo di funzione SYSTEM. Si può copiare in pocLIBC.py nella variabile system_addr

- `grep "bin/sh"` (in GDB) per trovare l'indirizzo di funzione bin/sh. Si può copiare in pocLIBC.py nella variabile binsh_addr

- Eseguiamo il programma: `run $(python3 pocLIBC.py)`

- Adesso però il programma esce in Segmentation fault. Per farlo terminare in modo opportuno, basta mettere l'indirizzo della funzione EXIT di libc (si può trovare eseguendo `p exit` in GDB) nella variabile return_addr

- `filename.exe $(python3 pocLIBC.py)` per eseguire l'exploit fuori dal GDB

- Per trovare gli offset dall'indirizzo di base di LIBC all'indirizzo di SYSTEM:

```bash
strings -a -t x /lib/i386-linux-gnu/libc.so.6 | grep '/bin/sh'
```

oppure

```bash
readelf
```


- Riattiviamo la randomizzazione degli indirizzi:

```bash
echo 2 | sudo tee /proc/sys/jernel/randomize_va_space
```

- In questo caso però, l'indirizzo base della libc non cambia completamente, ma cambiano solo i 2 bytes centrali dell'indirizzo. Quindi possiamo tentare un attacco bruteforce.

- Gli indirizzi di system e /bin/sh non cambiano, quindi dobbiamo solo trovare l'indirizzo base di libc