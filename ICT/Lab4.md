### Buffer overflow con meccanismi di sicurezza attivi (2)

- Impostiamo misure di sicurezza a nulla:

```bash
echo 0 | sudo 
```  

- **Canary**: ogni volta che viene eseguito un file, viene inserita una stringa di 4 byte nello stack alla fine del buffer, subito dopo le variabili locali. Quando l'esecuzione del file termina, il programma verifica che il canary sia ancora sullo stack: se non c'è, significa che è avvenuto un buffer overflow (il canary è stato sovrascritto).

#### Come bypassare il canary?

- Il canary di solito ha un byte 00 (*NULL byte*) alla fine. 

- Nel payload malevolo possiamo inserire il canary alla fine della stringa che causerà il buffer overflow.

#### Come troviamo il canary?

- Se abbiamo disattivato **PIE** (*Position Independent Executable*), possiamo sapere precisamente dove viene posizionato il canary.

- Vulnerabilità *format string*: *printf* ci permette di stampare anche valori contenuti nello stack.

- *strcopy* e *printf* hanno vulnerabilità: quando incontrano un NULL byte, interrompono la loro esecuzione

- *gets* non ha la stessa vulnerabilità di cui sopra, ma verrà usato per il buffer overflow (dato che gets non effettua alcun controllo sulla lunghezza del buffer dato in input)

- Usiamo il nuovo eseguibile vulnerable.c:

```bash
gcc -m32 -no-pie -fno-stack-protector -o vuln vulnerable.c
```

- Per verificare che i meccanismi di sicurezza siano disattivati, eseguire:

```bash
checksec --file=vuln
```

- In gdb:

    - `b address_gets`

    - `run malicious_input (a*80)`

    - `x/100x $esp` (stampa le prime 100 righe dello stack)

    - Con gef, per trovare il canary:

      - `canary`

- `./vuln %p` (restituisce un indirizzo dello stack in ordine, dall'inizio)

- `./vuln '%p %p'`

- `./vuln '%p %p %p'`

- `./vuln '%4$p'` (restituisce l'indirizzo 4 dello stack)

- `pip install pwntools`

- Eseguiamo il file python  

#### Bypassare ASLR?

- Attacco **Ret2PLT** (*Return to PLT*)

- **ROP** (*Return oriented programming*) (su macchine 64-bit)

- Su 64-bit non possiamo usare system + return_addr + binsh, ma dobbiamo usare i registri (RDI, RSI, RDX, RCX, R8, R9). I primi 6 argomenti di una funzione vanno su questi registri, mentre 7 e 8 argomento vanno sullo stack.

- Su Windows si usano solo 4 registri

##### ROP (Return Oriented Programming)

- Bisogna trovare un gadget che esegua *pop rdi*;

- Quindi passiamo alla funzione:

	*junk + pop rdi; ret + binsh + system + return_addr*

  
  https://ir0nstone.gitbook.io/notes/binexp/stack/aslr/plt_and_got


- `ropper --search "pop rdi; ret" vuln64`

- `objdump -D vuln64 | grep main`