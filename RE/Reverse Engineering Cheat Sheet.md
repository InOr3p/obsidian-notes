
## **Useful Linux commands**

| **Command**                      | **Purpose**             | **Why it matters**                                                                |
| -------------------------------- | ----------------------- | --------------------------------------------------------------------------------- |
| `file <bin>`                     | **File Identification** | Tells you if it's ELF (Linux), PE (Windows), 32/64 bit, or "stripped."            |
| `strings <bin>`                  | **Text Extraction**     | Finds hardcoded URLs, IP addresses, flag hints, or error messages.                |
| `nm <bin>`                       | **Symbol Listing**      | Shows function names and global variables (if the binary isn't stripped).         |
| `ldd <bin>`                      | **Library Deps**        | Shows which shared libraries (`.so` files) the program loads.                     |
| `ldd -u <bin>`                   | **Library Deps**        | Shows the unused shared libraries.                                                |
| `readelf -h <bin>`               | **Header Info**         | Displays the Entry Point (where the code starts) and Architecture.                |
| `objdump -d <bin>`               | **Disassembler**        | Converts machine code into assembly. Use `-M intel` for readable syntax.          |
| `objdump -s -j <.section> <bin>` | **Section content**     | Shows the full content of a section of the file.                                  |
| `strace <bin>`                   | **Syscall Trace**       | Logs every time the program asks the OS to do something (read file, open socket). |
| `ltrace <bin>`                   | **Library Trace**       | Logs calls to dynamic libraries (e.g., `strcpy`, `malloc`, `printf`, `strcmp`).   |

## **x86_64 Register Map**

In 64-bit systems, registers are 64 bits wide (starting with **R**). 32-bit versions start with **E**.

### General Purpose Registers

| **Register** | **Common Usage / Purpose**                                                                |
| ------------ | ----------------------------------------------------------------------------------------- |
| **RAX**      | **Accumulator:** Stores function return values.                                           |
| **RBX**      | **Base:** Pointing to data in the data segment.                                           |
| **RCX**      | **Counter:** Used in loops and string operations.                                         |
| **RDX**      | **Data:** Used in I/O operations and division/multiplication.                             |
| **RSI**      | **Source Index:** Pointer to the source for data copies.                                  |
| **RDI**      | **Destination Index:** Pointer to the destination for data copies.                        |
| **RBP**      | **Base Pointer:** Points to the bottom of the current stack frame.                        |
| **RSP**      | **Stack Pointer:** Points to the very top of the stack.                                   |
| **RIP**      | **Instruction Pointer:** The "Program Counter"—points to the next instruction to execute. |

### Function Calling Convention (Linux/System V)

When a function is called, arguments are passed in this specific order:

1. `RDI` (1st arg)
    
2. `RSI` (2nd arg)
    
3. `RDX` (3rd arg)
    
4. `RCX` (4th arg)
    
5. `R8` (5th arg)
    
6. `R9` (6th arg) _Anything beyond 6 arguments is pushed onto the **Stack**_


## **Assembly Knowledge**

Assembly is the "source code" of reverse engineering.

### Basic Instructions

- `MOV dest, src`: Copies value from `src` to `dest`.
    
- `LEA dest, [src]`: **Load Effective Address**. It calculates a memory address but doesn't fetch the data inside it (often used for math like `lea rax, [rbx+4]`: in this case, `rax` will contain the new calculated address, which is `rbx+4`).
    
- `ADD / SUB`: Arithmetic on registers.
    
- `XOR rax, rax`: A fast way to set a register to **0**.
    
- `PUSH / POP`: Puts a value on or takes a value off the **Stack**.
    
### Control Flow

Binary logic relies on the **Flags Register** (like the Zero Flag).

- `CMP rax, rbx`:  Used to compare `rax` and `rbx`. Internally, it does `rax - rbx` and sets flags based on the result (these flags tell the CPU if the result was zero, negative, or caused an overflow).
    
- `TEST rax, rax`: Checks if `rax` is zero or null.
    
- `JZ / JE`: Jump if Zero / Jump if Equal.
    
- `JNZ / JNE`: Jump if Not Zero / Jump if Not Equal.
    
- `JMP`: Unconditional jump (like a `goto`).
    
### Prologue and Epilogue functions

Every function usually starts and ends with a "handshake" to manage the stack.

- **Prologue:** `push rbp; mov rbp, rsp` (Sets up a new stack frame).
    
- **Epilogue:** `leave; ret` (Cleans up the frame and returns to the caller).

## **Other useful tools (with GUI or TUI)**

### 1. Ghidra (SRE Framework)

- **Definition:** An open-source suite by the NSA. Its killer feature is the **Decompiler**. It provides also an integrated Debugger and Disassembler.
    
- **How to use:**
    
    1. `File` -> `New Project` -> `Non-Shared`.
        
    2. Press `I` to import the binary.
        
    3. Double-click the file to open the **CodeBrowser**.
        
    4. Click **Analyze**. The right-hand window will show C-like pseudocode.
        

### 2. GDB + GEF / Pwndbg (Dynamic Debuggers)

- **Definition:** The standard Linux debugger, with plugins like GEF.
    
- **How to use:**
    
    - `gdb ./binary`
        
    - `b main`: Set a breakpoint at the start of the main function.
		
	- `b *<addr>`: Set a breakpoint at `<addr>` memory address.
        
    - `run` or simply `r`: Execute until a breakpoint.
		
	- `continue` or simply `c`: Continue the code execution.
        
    - `ni` / `si`: Next Instruction / Step Into.
		
	- `disass main`: Disassemble the main function into assembly code.
		
	- `x/s <addr>`: Examine the memory at that address as a string (you can also examine as an address `x/a`, as a number of characters `x/10c`, as hex `x/x` and as instruction `x/i`).
		
	- `x/s $eax`: It doesn't show you what is inside the register `$eax`; it uses the value in the register as a "map coordinate" to go look at a spot in memory.
		
	- `p/d $eax`: It shows the **actual content** of the register itself.

### 3. IDA Pro / Free

- **Definition:** The industry standard for **Graph View** analysis.
    
- **Best for:** Visualizing complex `if/else` logic and jumps.

### 4. Binary Ninja

- **Definition:** A modern, commercial disassembler with a very clean UI and powerful API.
    
- **How to use:** Great for "Intermediate Representation" (BNIL) which simplifies complex assembly into a more readable format.