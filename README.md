# LAB 1
---
---
---
## Bof1
### The program consists of three main functions:
- **secretFunc()** : Prints the message "Congratulation!" but is not directly called by the main program flow.
- **vuln()**: Contains the buffer overflow vulnerability due to the use of the gets() function, which can cause a buffer overflow by not limiting the number of input characters.
- **main()**: Calls the vuln() function after checking for command-line arguments.

### Exploitation Process Analysis
- **Buffer Overflow**: The vulnerability occurs in the vuln() function when the gets() function doesn't check the number of input characters, allowing memory to be overwritten and causing a memory error.
- **Targeting secretFunc()**: By exploiting this vulnerability, we can overwrite the return address of the vuln() function in the stack and replace it with the address of secretFunc(), forcing the program to execute secretFunc().

### Execution Details
#### Compile the program with security options disabled:
- -fno-stack-protector: Disables stack protection, making the exploit easier.
- -mpreferred-stack-boundary=2: Ensures stack alignment at 4 bytes, suitable for x86 architecture.

![image](/bof11.png)

#### Analyzing with gdb:
- Use gdb to disassemble the secretFunc and get its starting address (here 0x0804846b).

![](/bof12.png)

### Exploitation Payload

![image](/bof13.png)

- 'a'*204: Overwrites the buffer array[200] and the old EBP value.
- '\x6b\x84\x04\x08': Overwrites the Return Address with the address of secretFunc().

-When the vuln() function is called, its stack frame has the following structure:

![image](/bof14.png)

-After the buffer overflow, the stack will look like this:

![image](/bof15.png)

-When the vuln() function finishes, instead of returning to the expected location in main(), it will jump to the address of secretFunc() because the Return Address has been overwritten.

---
---
---
## Bof2
### Compiling the Program
-You compiled the bof2.c program with the following options:
- -w: Suppresses warnings.
- -g: Enables debugging information.
- -fno-stack-protector: Disables stack protection, making it easier to exploit buffer overflow.
- -mpreferred-stack-boundary=2: Sets the stack boundary.
  
![image](/bof21.png)

### Buffer Overflow Process

![image](/bof22.png)

-The vulnerability occurs from the call to fgets(buf, 45, stdin). Since buf is only 40 bytes, reading 45 bytes can overflow the buffer and overwrite adjacent memory:
- The first 40 bytes fill the buffer.
- The next 4 bytes overwrite the ‘check’ variable.
- If additional bytes are provided, they can overwrite the saved EBP and Return Address.

### Exploitation Payload
-To exploit this vulnerability, an attacker needs to create an input string that overwrites the check variable with the value 0xdeadbeef. The input must be at least 45 bytes long:

- Fill the buffer: Use 40 characters (e.g., 'a').
- Overwrite check: Append 4 bytes representing 0xdeadbeef.

-After a buffer-overflow occurs, the stack will look like this:

![image](/bof23.png)

-When the program checks check, its value is now 0xdeadbeef, leading to the output:

![image](/bof24.png)


---
---
---
## Bof3
### Buffer Overflow Vulnerability
- Cause: The use of fgets(buf, 133, stdin) allows reading 133 bytes into a buffer that can only hold 128 bytes. This leads to a buffer overflow.
- Consequence: If the user inputs more than 128 bytes, the excess bytes will overwrite adjacent memory, including the function pointer func.
### Exploitation of the Vulnerability
-Identifying the Address of shell()
- Using GDB, the address of the shell() function is determined to be 0x0804845b.
  
![image](/bof31.png)

### Creating the Payload
-To exploit the vulnerability, an attacker needs to create an input string structured as follows:
- 128 bytes: Fill the buffer with any character (e.g., 'a').
- 4 bytes: Overwrite the function pointer func to point to the address of shell(), specifically 0x0804845b (represented as '\x5b\x84\x04\x08').
### Executing the Exploit
-The following command is used to execute the exploit:

![image](/bof32.png)

-The call to func() after overwriting it with the address of shell() results in the execution of the shell() function instead of sup(). This demonstrates how a buffer overflow vulnerability can be exploited to manipulate the program's execution flow.

-After a buffer-overflow occurs, the stack will look like this:

![image](/bof33.png)

### Explanation

- **Buffer (128 bytes)**: Initially filled with 128 bytes of input (e.g., 'a').
- **Overwritten Function Pointer**: After the buffer, the next 4 bytes overwrite the original function pointer func, redirecting it to the shell() function.
- **Overwritten Return Address and Saved EBP**: If the overflow continues, it can overwrite the saved EBP and the return address, allowing control over the execution flow of the program.





---
---
---
# Lab 2
## CTF
### Source Code Analysis
- Function **myfunc(int p, int q)**:
    - Reads a flag from flag1.txt.
    - Checks two parameters (p and q) against specific values.
    - If both parameters match the expected values, it prints a flag message.
- Function **vuln(char * s)**:
    - Contains a buffer buf of size 100 bytes.
    - Uses strcpy() to copy the input string s into buf without size checking, leading to a buffer overflow vulnerability.
- Function **main()**:
    - Calls vuln() with the first argument from the command line.

### Buffer Overflow Vulnerability

- Cause: Using strcpy() without checking the input string's length allows the user to provide a string longer than 100 bytes, leading to overwriting adjacent memory on the stack.
- Consequence: When the buffer buf overflows, it can overwrite the return address of the vuln() function. This allows an attacker to change the program's control flow, leading to a call to myfunc().

![image](/ctf1.png)

![image](/ctf2.png)

-Payload Structure:
- 104 bytes of 'a': Used to fill the buffer and overwrite the old EBP.
- Address of myfunc: Overwrites the return address with the address of the myfunc function, causing the program to jump to it after execution.
- 4 arbitrary bytes: To overwrite the saved EBP (filling the space).
- Parameter p: Address \x11\x12\x08\x04.
- Parameter q: Address \x62\x42\x64\x44.


![image](/ctf3.png)
