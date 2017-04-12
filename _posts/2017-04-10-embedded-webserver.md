---
layout: post
title: Reverse Engineering of an Embedded Webserver
draft: true
hidden: true
---

In this article we look into the implementation of the embedded webserver that runs on the HooToo Travel Mate 6 router (the device). The webserver is at the core of the TM-06 user interface. It is also the best attack surface to start with. It is best due to the complexity of processing web requests and a historical precedent of web software being susceptible to memory corruption vulnerabilities.

# Locating the webserver
Looking at the HTTP traffic we see that there are two webservers at play. First is the `lighttpd/1.4.28` and another is the `vshttpd`. Different server values are returned even though same IP/port combinations are used. Clearly there is some sort of proxying set up. So, let's go looking for these servers.

Scanning through _/etc/init.d_ directory, we find that `fileserv.sh` has references _/etc/fileserv/lighttpd.conf_. That's cool, it means that _/usr/sbin/fileserv_ is the _lighttpd_ server we are looking for. The binary is referenced by the same shell script. Scanning further, we find an _/etc/init.d/web_ file which has references to the _/usr/sbin/ioos_ file. Based on the name and the process of elimination let's decide that this is our other webserver which calls itself `vshttpd`. This will be confirmed by reverse engineering.

```
$ strings /usr/sbin/ioos | grep vshttpd
Server: vshttpd

$ strings /usr/sbin/fileserv | grep light
Server: lighttpd/1.4.28
```

We get some good confirmation using strings. The _file_ command gives us some good information on what to expect.

```
/usr/sbin/fileserv: ELF 32-bit LSB executable, MIPS, MIPS-II version 1 (SYSV), 
                    dynamically linked, interpreter /lib/ld-uClibc.so.0, stripped
/usr/sbin/ioos:     ELF 32-bit LSB executable, MIPS, MIPS-II version 1 (SYSV), 
                    dynamically linked, interpreter /lib/ld-uClibc.so.0, stripped
```

# MIPS Overview
The device runs a version of a MIPS processor. The instruction set is documented here: [MIPS32 24K](https://people.freebsd.org/~adrian/mips/MD00343-2B-24K-SUM-03.11.pdf). It is a relatively simple architecture with a small instruction set. I would encourage everyone to learn it because it is prevalent in the embedded devices world, and MIPS is a great starting point to learn about assembly.

By convention there's a stack at a high address, similar to that of the x86 systems. On the TM-06 the stack actually moves around due to the memory randomization anti-exploitation measure. The stack is managed by the compiler where it will add/subtract from the `$sp` register on function return/calls. The `$sp` register stores the current stack pointer. A function preamble would look something like this:

```asm
	li      $gp, 0x18424C          # Load Immediate
	addu    $gp, $t9               # Add Unsigned
	addiu   $sp, -0x38             # Add Immediate Unsigned
	sw      $ra, 0x38+var_4($sp)   # Store Word
	sw      $s0, 0x38+var_8($sp)   # Store Word
	sw      $gp, 0x38+var_20($sp)  # Store Word
	sw      $a0, 0x38+arg_0($sp)   # Store Word
```

There's a global pointer `$gp` for every function - however, in code compiled by the device developers, the global point does not appear to be used for anything of significance. `$t9` is a register used for function calls. Commonly, an address would be loaded into `$t9` and the program will branch using that register. The `$ra` register is used for storing the return address. This is why in the preamble we see it being saved on the stack, so the function knows where to go once it is done.

```asm
	sw      $zero, 0xC($v0)       # Store Word
	lw      $ra, 0x38+var_4($sp)  # Load Word
	lw      $s0, 0x38+var_8($sp)  # Load Word
	addiu   $sp, 0x38             # Add Immediate Unsigned
	jr      $ra                   # Jump Register
	nop
```

The above function epilog shows how the return address is used to return the control back to the caller function. The arguments are stored in registers `$a0` to `$a4` and usually they are stored on the stack before the function does any actual logic. Certain registers such as the `$s0` are preserved by the callee.

Finally, MIPS is a pipelined architecture where the developer needs to be aware of its semantics. This is specifically important for branching instructions because the instruction after the branch will start execution before the branching actually finishes. Now, the code we will be looking at is not built by an optimizing compiler and so, branching instructions, such as the `jr $ra` above, will always have a `nop` following.

I've never, until now, reversed MIPS and from personal experience can say that it is a very easy architecture to get a hang of. So, if this is a your first time then just take one step at a time and try to follow through with the examples in this article. You will get used to the architecture and things will become exponentially easier!

# Extracting the source
Compilers are really smart tools, but in the end they are just a transformation function of the source code. So, if the source code has certain patterns then it may be possible to detect and use them to learn about the binary code. In the case of the webserver from the device, the compiler does not perform a lot of optimizations and so we are able to extract quite a lot of information. Next sections will focus on some of the more obvious patterns that I've been able to use for my advantage. Going through these examples is useful to learn about the reverse engineering process as well as how to use various IDA interfaces.

## Finding functions
While perusing the assembly code, I've started noticing a simple pattern for error handling recurring over and over. There would be some sort of a check and if the check failed then an error message would be generated. The message is then printed out to the STDERR stream. The assembly looks something like this: 

```asm
addiu   $a0, (aHomeProduct_30 - 0x550000)  # "/home/product/mk_wdisk_7620/UIS-V3.0/li"...
...
addiu   $a1, (aSSDMtdUnlock_0 - 0x550000)  # "(%s,%s,%d)\nMTD Unlock failure\n"
...
addiu   $a3, (aFlash_non_regi - 0x550000)  # "flash_non_region_erase"
la      $t9, fprintf     # Load Address
```

There would be a string showing which function failed, something to describe the error (often exposing local compiled out variable names) and the file location of the function. Great information! We could use this to deduce names of functions before the compiler stripped them out.

There are so many of these error handling blocks that we can't reasonably go through all of them by hand. So, I want to automate the process of mapping the function names from the error messages to the IDAPro disassembly database. To that end, I wrote a couple of IDAPython functions to help me out. These functions will be specific to the MIPS disassembly that I saw in this webserver. However, the logic is probably applicable to other applications as well.

Let's dive in. First thing I notice is that the function responsible for error reporting uses `fprintf` this means that the strings I'm seeing are placed into the argument registers. The function below follows that pattern and abuses specifics of the IDA output syntax to extract the information.

```python
def findPrintfStrings(addr):
 ret = {'file': ''}

 # find the function name, listing printf args
 for a in range(addr - 10*4, addr, 4):
   disasm = GetDisasm(a)
   if(disasm[0:4] == "addi" and GetOpnd(a, 0)[0:2] == '$a'):
     ret[GetOpnd(a, 0)] = disasm.split('#')[1].strip()

 # find he source code file
 for a in range(addr - 30*4, addr, 4):
   disasm = GetDisasm(a)
   if(disasm[0:4] == "addi" and GetOpnd(a, 0) == '$a0' and disasm.split('#')[1][0:7] == ' "/home'):
     ret['file'] = GetString(GetOperandValue(a, 1) + 0x540000, -1, ASCSTR_C)

 return ret
```

Given an address of a call to `fprintf` the function will trace back several instructions and find all strings that are stored in the arguments. Noticing that the function name is located in the first variable argument to `fprintf`, I don't need to worry about the arguments placed placed on the stack. The first loop looks at the `addi` instructions that refer to the `$a0 - $a4` registers. These are the instructions that set the arguments. The second loop looks for references to strings that start with `/home` since that is where the source code was, apparently, compiled. Together we get a nice picture of what the error message looks like. We can see the name of the current function and its file location. For the assembly shown above, this is the output we get:

```python
Python>findPrintfStrings(ScreenEA())
{'$a1': '"(%s,%s,%d)\\nMTD Unlock failure\\n"', 
 'file': '/home/product/mk_wdisk_7620/UIS-V3.0/lib/flash/flash.c', 
 '$a3': '"flash_non_region_erase"'}
```

OK, given that we can find information about a function with one error message, how we do we find all of them and do the mapping? I like to take an iterative  approach by refining the information at hand with each step. This way there's more space for tweaking and adjusting for accuracy depending on our needs. So, the function below will first look for all uses of `fprintf`.

```python
def findFuncNames():
 ret = []
 for i in XrefsTo(LocByName("fprintf")):
   if(GetDisasm(i.frm)[0:2] == "la"):
     args = findPrintfStrings(i.frm)

     # filter by error message pattern
     if(args["$a1"][0:5] == '"(%s,'):
       func = idaapi.get_func(i.frm)
       name = "no_func"

       # sometimes functions aren't recognized by IDA
       if(func is not None):
         name = GetFunctionName(func.startEA)

       ret.append( (hex(i.frm), name, args["$a3"].replace('"', ''), args['file'] ) )

 return ret
```

Once an `fprintf` is located, the script will look for `la` (load address) instructions. That is where the address for the function is loaded before bing used. I chose the `la` vs the `jalr` instruction as a means of reducing the number of instructions I have to consider. Then we call the `findPrintfStrings` function from earlier to extract the strings. Once the strings are extracted we can filter on a common filter for all error messages. We notice that, first, the error specifies the context before moving on to other information. So, we look for `"(%s,` to remove irrelevant `fprintf` occurrences.

Finally, using the IDA api we look up the function address that contains the error message and add that to the list. The final output looks something like this:

```python
('0x52d5c4L', 'sub_52D0CC', 'flash_region_erase', '/home/product/mk_wdisk_7620/UIS-V3.0/lib/flash/flash.c')
('0x52d8d0L', 'sub_52D734', 'flash_non_region_erase', '/home/product/mk_wdisk_7620/UIS-V3.0/lib/flash/flash.c')
('0x52d96cL', 'sub_52D734', 'flash_non_region_erase', '/home/product/mk_wdisk_7620/UIS-V3.0/lib/flash/flash.c')
```

There are 910 of such error code blocks. Some function mappings are duplicates because a function could contain more than one error block. The duplication is useful for confirming that a mapping is correct. 

## Discovering internal structures

During the long process of reverse engineering the webserver MIPS assembly, several programming patterns have revealed themselves. First, the webserver is a single threaded state machine processing one HTTP request at a time. This greatly simplified how we reason about the system. Second, the implementation of the server is in C, however the developers are clearly fans of Objective-C or C++. That is because most structures come combined with data and function pointers. To call these functions, the code always passes the structure pointer as the first parameter. However, I do not believe that the source code is in C++ because there are no obvious artifacts, such as mangled names or vtables, to be found anywhere. The following pseudo code is a very common pattern that we see in the assembly:

```c
typedef void (*fcn_ptr)(struct state* self, ...);

struct state {
   char[20] name;
   int      state;
   fcn_ptr  func1;
   fcn_ptr  func2;
};

struct state* s = malloc(sizeof(struct state));
s->func1 = func1_implementation;
s->func2 = func2_implementation;

s->func1(s, 2, 3);
```

Let's find an example of this pattern. In `web_cgi_main_handler` there's a call create a structure for the `httpd` server. It is allocated and initialized at address `.text:00412B34` with a call to `httpd_new`.

```asm
web_cgi_main_handler:
...
.text:00412B24 addiu   $v0, 0xC         # Add Immediate Unsigned
.text:00412B28 move    $a0, $v0
.text:00412B2C la      $t9, httpd_new   # Load Address
.text:00412B34 jalr    $t9 ; httpd_new  # Jump And Link Register
```

Within the `httpd_new` function a buffer is allocated using `calloc`.

```asm
httpd_new:
...
.text:00413770 li      $a0, 1           # nmemb
.text:00413774 li      $a1, 0x90        # size
.text:00413778 la      $t9, calloc      # Load Address
.text:0041377C nop
.text:00413780 jalr    $t9 ; calloc     # Jump And Link Register
```

This buffer is used to store a whole bunch of function pointers (please excuse skipped instructions for brevity - note the addresses).

```asm
httpd_new:
...
.text:004138A0 addiu   $v0, (sub_41395C - 0x410000)  # Add Immediate Unsigned
.text:004138A8 sw      $v0, 0x74($v1)   # Store Word
.text:004138B8 addiu   $v0, (sub_413AE8 - 0x410000)  # Add Immediate Unsigned
.text:004138C0 sw      $v0, 0x78($v1)   # Store Word
.text:004138D0 addiu   $v0, (sub_414064 - 0x410000)  # Add Immediate Unsigned
.text:004138D8 sw      $v0, 0x7C($v1)   # Store Word
.text:004138E8 addiu   $v0, (sub_4144C8 - 0x410000)  # Add Immediate Unsigned
.text:004138F0 sw      $v0, 0x80($v1)   # Store Word
.text:00413900 addiu   $v0, (sub_4148A0 - 0x410000)  # Add Immediate Unsigned
.text:00413908 sw      $v0, 0x84($v1)   # Store Word
.text:00413918 addiu   $v0, (sub_414B14 - 0x410000)  # Add Immediate Unsigned
.text:00413920 sw      $v0, 0x88($v1)   # Store Word
.text:00413930 addiu   $v0, (sub_414D5C - 0x410000)  # Add Immediate Unsigned
.text:00413938 sw      $v0, 0x8C($v1)   # Store Word
```

`httpd_new` will return a pointer to this new heap allocated structure back to `web_cgi_main_handler`. The handler function will then be able to call these function pointers to do further operations.

```asm
web_cgi_main_handler:
...
.text:00412BD0 sw      $v0, 0x38+httpd_struct($sp)  # httpd stuct
.text:00412BD4 lw      $v0, 0x38+httpd_struct($sp)  # Load Word
.text:00412BDC lw      $t9, 0x78($v0)   # Load Word
.text:00412BE0 lw      $a0, 0x38+httpd_struct($sp)  # Load Word
.text:00412BE4 la      $a1, loc_410000  # Load Address
.text:00412BEC addiu   $a1, (prgcgi_main_handler - 0x410000)  # Add Immediate Unsigned
.text:00412BF0 jalr    $t9              # Jump And Link Register
```

In the example above we can see that `$v0` register contains a pointer to the `httpd_t` structure. Then at offset `0x78` a pointer is retrieved and executed. Before it is executed the first argument at `$a0` register is set to the address of the same `httpd_t` structure. In essence the function is called with a `this` pointer as the first argument. We see this pattern over and over with various core data structures.

This pattern is really great news for any sort of buffer overflow vulnerabilities on the heap. That is because there are unprotected function pointers all over the place and there would be no need for any sort of heap pointer manipulations to gain execution - your experience may vary ;-).

One way to locate these patterns is to use the function finder script we built is the previous section. All we have to do is filter on `*_new` for function names.

```python
Python>for i in [ (x[0], x[1], x[3]) 
          for x in findFuncNames() 
             if (x[3].find("new") != -1)]: print i
('0x40ca7cL', 'str_parse_new', 'str_parse_new')
('0x40cb30L', 'str_parse_new', 'str_parse_new')
('0x40cc28L', 'str_parse_new', 'str_parse_new')
('0x40cfb4L', 'str_build_new', 'str_build_new')
('0x40d078L', 'str_build_new', 'str_build_new')
('0x4137f0L', 'httpd_new', 'httpd_new')
('0x413860L', 'httpd_new', 'httpd_new')
# ... truncated
```

Using this method we find a whole bunch of initialization functions including the one we analyzed as an example, `httpd_new`. One unfortunate side affect of this C++ style pattern is that functions called via these structures do not get picked up as cross references by IDA.

## Loading pattern

I've already mentioned that the compiler used by the developers of the device is not an optimizing compiler. Or, at least, if it was optimizing, it wasn't doing a great job. So let's have a look at some of the weird patterns that have emerged.

```asm
.text:00412B34 jalr    $t9 ; httpd_new  # Jump And Link Register
.text:00412B38 nop
```

First, every jump or branch is followed by a NOP instruction. This creates for a nice break in code and makes it less dense. I find that it becomes easier to read the assembly code because there are less things that I have to consider. For contrast, here's a function epilogue from _libiconv_ from the same device:

```asm
(libiconv.so.2.5.0)
.text:0001706C lw      $s0, 0x20+var_8($sp)
.text:00017070 move    $v0, $a0
.text:00017074 jr      $ra
.text:00017078 addiu   $sp, 0x20
```

We can see here that the function returns and automatically fixes up the stack. This allows for a more efficient implementation but it puts a little more load on our brains when doing reverse engineering. OK, let's switch back to the webserver function.

```asm
.text:00412B3C lw      $gp, 0x38+var_20($sp)  # Load Word
.text:00412B40 sw      $v0, 0xC($s0)    # Store Word
.text:00412B44 lw      $v0, 0xC($s0)    # Load Word
```

I find this phenomenon quite often. There will be an instruction that stores a variable and the immediately loads it back up into the same register as if the storing process has somehow cleared the register. Clearly, it is an artifact of a lack of an optimization step. This is fine for us, it allows the reverse engineer to see how the source code was written. Such structures create less dense and more mentally patterned assembly which is easier to follow.

```asm
.text:00412B48 nop
.text:00412B4C bnez    $v0, loc_412BC0  # Branch on Not Zero
.text:00412B50 nop
```

Finally, a bunch of NOPs around branching. The compiler is being safe about the two stage pipeline to make sure that when the registers are used they are in fact fully actualized.

# Conclusion
We went through some interesting patterns for the implementation of the server. Hopefully, it has given you enough of an intuition for your own reverse engineering efforts in the future. We got really lucky in this case because the compiler was not aggressively optimizing the code and so we got to see a lot of patterns that make reversing of this server much easier.

The binaries referenced in this article can be downloaded here:
* SHA ([7620-WiFiDGRJ-HooToo-633-HT-TM06-2.000.030_fileserv](../../../../resources/7620-WiFiDGRJ-HooToo-633-HT-TM06-2.000.030_fileserv)) = 86b96a77f8f09ac4937e079e9db1e1e3c9a2d24f
* SHA ([7620-WiFiDGRJ-HooToo-633-HT-TM06-2.000.030_ioos](../../../../resources/7620-WiFiDGRJ-HooToo-633-HT-TM06-2.000.030_ioos)) = 7420757f92f140708e4628efe589924cfcc1fade







