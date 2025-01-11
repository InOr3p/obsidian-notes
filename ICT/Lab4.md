### Buffer overflow con meccanismi di sicurezza attivi (2)

- **Canary**: ogni volta che viene eseguito un file, viene inserita a *run-time* una stringa di 4 byte nello stack alla fine del buffer, subito dopo le variabili locali. Poco prima che l'esecuzione del file termini, il programma verifica che il canary sia ancora sullo stack: se non c'è, significa che è avvenuto un buffer overflow (il canary è stato sovrascritto). Ad ogni esecuzione, il canary è sempre diverso, ma è riconoscibile perchè termina con un byte 00 (*NULL byte*).

#### Come bypassare il canary?

- Nel payload malevolo possiamo inserire il canary alla fine della stringa che causerà il buffer overflow.

#### Come troviamo il canary?

- Se abbiamo disattivato **PIE** (*Position Independent Executable*), possiamo sapere precisamente dove viene posizionato il canary.

- Sfruttiamo la vulnerabilità **format string**: *printf* ci permette di stampare anche valori contenuti nello stack.

- *strcpy* e *printf* hanno una vulnerabilità: quando incontrano un NULL byte, interrompono la loro esecuzione

- *gets* non ha la stessa vulnerabilità di cui sopra, ma verrà usato per il buffer overflow (dato che gets non effettua alcun controllo sulla lunghezza del buffer dato in input)

- Usiamo il nuovo eseguibile *vulnerable.c*:

```bash
gcc -m32 -fstack-protector -no-pie -o vuln vulnerable.c
```

- Per verificare che i meccanismi di sicurezza siano disattivati, eseguire:

```bash
checksec --file=vuln
```

1. Con gef, per trovare il canary:

       `canary`

2. Per trovare l'offset del canary dall'inizio dello stack possiamo usare la _format string vulnerability_:

- `./vuln %p` (restituisce un indirizzo dello stack in ordine, dall'inizio)

- `./vuln '%p %p'`

- `./vuln '%p %p %p'`

- `./vuln '%4$p'` (restituisce l'indirizzo in posizione 4 dello stack)

- Con una sorta di ricerca binaria lo possiamo trovare facilmente (facendo attenzione al NULL byte finale). In questo caso, per ricerca binaria si intende tentare di trovare il canary in intervalli sullo stack (ad esempio nelle prime 8 posizioni dello stack a partire dall'inizio, cioè dallo *stack pointer*, quindi tra `'%1$p'` e `'$8$p'`)

- La posizione a cui troveremo il canary sarà il suo offset (quindi avendo trovato il canary a `'$27$p'`, l'offset sarà 27).

3. Usiamo la libreria **pwntools** per costruire il nostro nuovo *Proof of concept*:

- `pip install pwntools`

4. Aggiungiamo l'offset del canary al nuovo *poc*. Il resto verrà calcolato direttamente nello script: l'indirizzo di base della libc viene calcolato come al solito (eseguendo il comando  `ldd vuln32 | grep libc` dallo script), mentre per "bin/sh" e system function utilizziamo gli offset (che non cambiano) dall'indirizzo di base della libc.

5. Eseguiamo il file python:

```bash
python3 poc_canary.py
```

#### Bypassare ASLR?

- Attacco **Ret2PLT** (*Return to PLT*)

- **ROP** (*Return Oriented Programming*) (su macchine 64-bit): è una tecnica che permette di prendere il controllo del flusso di esecuzione di un programma sfruttando sequenze di istruzioni già presenti nel binario o nelle librerie condivise caricate in memoria chiamate **gadget**.

- Su 64-bit non possiamo usare system + return_addr + binsh, ma dobbiamo usare i registri (RDI, RSI, RDX, RCX, R8, R9). I primi 6 argomenti di una funzione vanno su questi registri, mentre 7 e 8 argomento vanno sullo stack.

- Su Windows si usano solo 4 registri

##### ROP (Return Oriented Programming)

- Bisogna trovare un gadget che esegua *pop rdi;*

- Quindi passiamo alla funzione:

	*junk + pop rdi; ret + binsh + system + return_addr*

  
  https://ir0nstone.gitbook.io/notes/binexp/stack/aslr/plt_and_got

- **Ropper** è uno strumento usato per eseguire ROP. In particolare, permette di trovare gadget ROP in un binario o nelle librerie caricate e generare catene ROP (**ROP chains**) per l'exploit.

```bash
ropper --search "pop rdi; ret" vuln64
```

```bash
objdump -D vuln64 | grep main
```
