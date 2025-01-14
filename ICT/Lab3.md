### Buffer overflow con meccanismi di sicurezza attivi (1)

- **NX**: *Not Executable*, quando attivo disabilita l'esecuzione di *shell code*

- Per riabilitarlo, si elimina *-z execstack*  dal comando usato per compilare il programma. Il comando adesso diventa:

```bash
gcc -m32 -no-pie -fno-stack-protector -o vuln32 vuln.c
```

- Per verificare se l’indirizzo di caricamento della **libc** è cambiato o rimasto sempre uguale:

 ```bash
 ldd vuln32 | grep libc
 ```


- Per caricare la libc sempre allo stesso indirizzo (ovvero disattivare ASLR a livello di sistema operativo):

```bash
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
```
  

- Se proviamo ad eseguire il nuovo programma con *poc.py*, adesso andrà sempre in **Segmentation fault**, perchè avendo riabilitato **NX** (stack non eseguibile), non potremo più eseguire lo shellcode. Per risolvere questo problema, ricorriamo a **Ret2libc** (*Return To libc*).

### Ret2Libc

- Sfruttiamo le funzioni della libc per ottenere una shell.

- Libc contiene una serie di funzioni. Ha solitamente un indirizzo di base e ogni funzione si trova ad offset di memoria prestabiliti dall'indirizzo di base:

    - 0x0 -> BASE ADDRESS (visibile con comando `ldd vuln32 | grep libc`)

    - 0x1 -> SYSTEM

    - 0x2 -> READ

    - 0x3 -> WRITE

    - 0x4 -> SETUID

    - 0x5 -> OPEN

    - 0x19 -> bin/sh (argomento della funzione)

1. Creiamo un nuovo *Proof of concept*

2.  Usiamo `p system` (in GDB con eseguibile runnato) per trovare l'indirizzo della funzione SYSTEM della libc e copiamolo in *pocLIBC.py* nella variabile *system_addr* 0xf7dcc170

3. Usiamo `find &__libc_start_main, +9999999, "/bin/sh"` o `grep '/bin/sh'` (in GDB) per trovare l'indirizzo di funzione *bin/sh* e copiamolo in *pocLIBC.py* nella variabile *binsh_addr*. Per verificare che sia l'indirizzo giusto, usiamo `x/s <indirizzo>` -> restituisce tutte le stringhe all’indirizzo `<indirizzo>` (se ce ne sono), quindi se restituisce `/bin/sh` è l’indirizzo giusto 

4. Eseguiamo il programma: `run $(python3 pocLIBC.py)`

5. Adesso però il programma esce in **Segmentation fault**. Per farlo terminare in modo opportuno, basta mettere l'indirizzo della funzione EXIT di libc (si può trovare eseguendo `p exit` in GDB) nella variabile *return_addr*

6.  `vuln $(python3 pocLIBC.py)` per eseguire l'exploit fuori dal GDB

- Ci sono varianti del *pocLIBC.py* in cui si specifica solo l'indirizzo di base della libc e si calcolano gli indirizzi di system, bin/sh ed exit utilizzando gli offset (distanza dall'indirizzo di base della libc) invece di indicare gli specifici indirizzi delle funzioni.

- Per trovare l'offset dall'indirizzo di base di libc all'indirizzo di SYSTEM:

```bash
readelf -s /lib/i386-linux-gnu/libc.so.6 | grep system
```

- Per trovare l'offset dall'indirizzo di base di libc all'indirizzo di bin/sh:

```bash
strings -a -t x /lib/i386-linux-gnu/libc.so.6 | grep '/bin/sh'
```


- Riattiviamo la randomizzazione degli indirizzi:

```bash
echo 2 | sudo tee /proc/sys/jernel/randomize_va_space
```

- In questo caso, l'indirizzo base della libc dovrebbe cambiare periodicamente (avendo attivato ASLR). In realtà, non cambia completamente, ma cambiano solo i 2 bytes centrali dell'indirizzo. Quindi possiamo tentare un attacco bruteforce per cercare di indovinare i 2 bytes centrali.

- Gli offset di system e /bin/sh non cambiano mai, quindi dobbiamo solo trovare l'indirizzo base di libc.