---
layout: post
title: Tracing Objective-C method calls
draft: false
---

Linux has this great tool called _strace_, on OSX there's a slightly worse tool called _dtrace_. Dtrace is not that bad, it gives pretty much everything you need. It is just not as nice to use as strace. However, on Linux there is also _ltrace_ for library tracing. That is arguably more useful because you can see much more granular application activity. Unfortunately, there isn't such a tool on OSX. So, I decided to make one - albeit a simpler version for now. I called it [objc_trace](https://github.com/nologic/objc_trace).

Objc_trace's functionality is quite limited at the moment. It will print out the name of the method, the class and a list of parameters to the method. In the future it will be expanded to do more things, however just knowing which method was called is enough for many debugging purposes.

## Something about the language

Without going into too much detail let's look into the relevant parts of the [Objective-C](https://en.wikipedia.org/wiki/Objective-C) runtime. This subject has been covered pretty well by the hacker community. In [Phrack](http://phrack.org/issues/66/4.html) there is a great article covering various internals of the language. However, I will scratch the surface to review some aspects that are useful for this context.

The language is incredibly dynamic. While still backwards compatible to C (or C++), most of the code is written using classes and methods a.k.a. structures and function pointers. A class is exactly what you're thinking of. It can have static or instance methods or fields. For example, you might have a class `Book` with a method `Pages` that returns the contents. You might call it this way:

```Objective-C
	Book* book = [[Book alloc] init];
	Page* pages = [book Pages];
```

The `alloc` function is a static method while the others (`init` and `Pages`) are dynamic. What actually happens is that the system sends messages to the object or the static class. The message contains the class name, the instance, the method name and any parameters. The runtime will resolve which compiled function actually implements this method and call that.

If anything above doesn't make sense you might want to read the referenced Phrack article for more details.

Message passing is great, though there are all kinds of efficiency considerations in play. For example, methods that you call will eventually get cached so that the resolution process occurs much faster. What's important to note is that there is some smoke and mirrors going on.

The system is actually not sending messages under the hood. What it is doing is routing the execution using a single library call: `objc_msgSend` [1]. This is due to how the concept of a message is implemented under the hood.

```objective-c
	id objc_msgSend(id self, SEL op, ...)
```

Let's take ourselves out of the Objective-C abstractions for a while and think about how things are implemented in C. When a method is called the stack and the registers are configured for the `objc_msgSend` call. `id` type is kind of like a `void *` but restricted to Objective-C class instances. `SEL` type is actually `char*` type and refers to selectors, more specifically the methods names (which include parameters). For example, a method that takes two parameters will have a selector that might look something like this: `createGroup:withCapacity:`. Colons signal that there should be a parameter there. Really quite confusing but we won't dwell on that. 

The useful part is that a selector is a C-String that contains the method name and its named parameters. A non-obfuscating compiler does not remove them because the names are needed to resolve the implementing function.

Shockingly, the function that implements the method takes in two extra parameters ahead of the user defined parameters. Those are the `self` and the `op`. If you look at the disassembly, it looks something like this (taken from Damn Vulnerable iOS App):

```assembly
__text:100005144
__text:100005144 ; YapDatabaseViewState - (id)createGroup:(id) withCapacity:(uint64_t)
__text:100005144 ; Attributes: bp-based frame
__text:100005144
__text:100005144 ; id __cdecl -[YapDatabaseViewState createGroup:withCapacity:]
                        ;         (struct YapDatabaseViewState *self, SEL, id, uint64_t)
__text:100005144 __YapDatabaseViewState_createGroup_withCapacity__
```

Notice that the C function is called `__YapDatabaseViewState_createGroup_withCapacity__`, the method is called `createGroup` and the class is `YapDatabaseViewState`. It takes two parameters: an `id` and a `uint64_t`. However, it also takes a `struct YapDatabaseViewState *self` and a `SEL`. This signature essentially matches the signature of `objc_msgSend`, except that the latter has variadic parameters.

The existence and the location of the extra parameters is not accidental. The reason for this is that `objc_msgSend` will actually redirect execution to the implementing function by looking up the selector to function mapping within the class object. Once it finds the target it simply jumps there without having to readjust the parameter registers. This is why I referred to this as a routing mechanism, rather than message passing. Of course, I say that due to the implementation details, rather than the conceptual basis for what is happening here.

Quite smart actually, because this allows the language to be very dynamic in nature i.e. I can remap SEL to Function mapping and change the implementation of any particular method. This is also great for reverse engineering because this system retains a lot of the labeling information that the developer puts into the source code. I quite like that.

## The plan

Now that we've seen how Objective-C makes method calls, we notice that `objc_msgSend` becomes a choke point for all method calls. It is like a hub in a poorly setup network with many many users. So, in order to get a list of every method called all we have to do is watch this function. One way to do this is via a debugger such as LLDB or GDB. However, the trouble is that a debugger is fairly heavy and mostly interactive. It's not really good when you want to capture a run or watch the process to pin point a bug. Also, the performance hit might be too much. For more offensive work, you can't embed one of those debuggers into a lite weight implant.

So, what we are going to do is hook the `objc_msgSend` function on an ARM64 iOS Objective-C program. This will allow us to specify a function to get called before `objc_msgSend` is actually executed. We will do this on a Jailbroken iPhone - so no security mechanism bypasses here, the Jailbreak takes care of all of that.


![](../../../../images/func_hooking.svg "Function hooking high level")

__Figure 1:__ Patching at high level


On the high level the hooking works something like this. `objc_msgSend` instructions are modified in the preamble to jump to another function. This other function will perform our custom tracing features, restore the CPU state and return to a jump table. The jump table is a dynamically generated piece of code that will execute the preamble instructions that we've overwritten and jump back to `objc_msgSend` to continue with normal execution.

## Hooking

The implementation of the technique presented can be found in the [objc_trace](https://github.com/nologic/objc_trace) repository.

The first thing we are going to do is allocate what I call a _jump page_. It is called so because this memory will be a page of code that jumps back to continue executing the original function.

```c
s_jump_page* t_func = 
   (s_jump_page*)mmap(NULL, 4096, 
    		PROT_READ | PROT_WRITE, 
    		MAP_ANON  | MAP_PRIVATE, -1, 0);
```

Notice that the type of the _jump page_ is `s_jump_page` which is a structure that will represent our soon to be generated code.

```c
typedef struct {
    instruction_t     inst[4];    
    s_jump_patch jump_patch[5];
    instruction_t     backup[4];    
} s_jump_page;
```

The `s_jump_page` structure contains four instructions that we overwrite (think back to the diagram at step 2). We also keep a backup of these instruction at the end of the structure - not strictly necessary but it makes for easier unhooking. Then there are five structures called _jump patches_. These are special sets of instructions that will redirect the CPU to an arbitrary location in memory. _Jump patches_ are also represented by a structure.

```c
typedef struct {
    instruction_t i1_ldr;
    instruction_t i2_br;
    address_t jmp_addr;
} s_jump_patch;
```

Using these structures we can build a very elegant and transparent mechanism for building dynamic code. All we have to do is create an inline assembly function in C and cast it to the structure.

```c
__attribute__((naked))
void d_jump_patch() {
    __asm__ __volatile__(
        // trampoline to somewhere else.
        "ldr x16, #8;\n"
        "br x16;\n"
        ".long 0;\n" // place for jump address
        ".long 0;\n"
    );
}
```

This is ARM64 Assembly to load a 64-bit value from address `PC+8` then jump to it. The `.long` placeholders are places for the target address.

```c
s_jump_patch* jump_patch(){
    return (s_jump_patch*)d_jump_patch;
}
```

In order to use this we simply cast the code i.e. the `d_jump_patch` function pointer to the structure and set the value of the `jmp_addr` field. This is how we implement the function that generates the custom trampoline.

```c
void write_jmp_patch(void* buffer, void* dst) {
    // returns the pointer to d_jump_patch.
    s_jump_patch patch = *(jump_patch());

    patch.jmp_addr = (address_t)dst;

    *(s_jump_patch*)buffer = patch;
}
```

We take advantage of the C compiler automatically copying the entire size of the structure instead of using `memcpy`. In order to patch the original `objc_msgSend` function we use `write_jmp_patch` function and point it to the `hook` function. Of course, before we can do that we copy the original instructions to the _jump page_ for later execution and back up.

```c
    //   Building the Trampoline
    *t_func = *(jump_page());
    
    // save first 4 32bit instructions
    //   original -> trampoline
    instruction_t* orig_preamble = (instruction_t*)o_func;
    for(int i = 0; i < 4; i++) {
        t_func->inst  [i] = orig_preamble[i];
        t_func->backup[i] = orig_preamble[i];
    }
```

Now that we have saved the original instructions from `objc_msgSend` we have to be aware that we've copied four instructions. A lot can happen in four instructions, all sorts of decisions and branches. In particular I'm worried about branches because they can be relative. So, what we need to do is validate that `t_func->inst` doesn't have any branches. If it does, they will need to modified to preserve functionality.

This is why `s_jump_page` has five _jump patches_:

1. All four instructions are non branches, so the first _jump patch_ will automatically redirect execution to `objc_msgSend+16` (skipping the patch).
2. There are up to four branch instructions, so each of the _jump patches_ will be used to redirect to the appropriate offset into `objc_msgSend`.

Checking for branch instructions is a bit tricky. ARM64 is a RISC architecture and does not present the same variety of instructions as, say, x86-64. But, there are still quite a few [2].

1. _Conditional Branches:_ 
 * __B.cond label__ jumps to PC relative offset.
 * __CBNZ Wn\|Xn, label__  jumps to PC relative offset if Wn is not equal to zero. 
 * __CBZ Wn\|Xn, label__  jumps to PC relative offset if Wn is equal to zero. 
 * __TBNZ Xn\|Wn, #uimm6, label__ jumps to PC relative offset if bit number uimm6 in register Xn is not zero. 
 * __TBZ Xn\|Wn, #uimm6, label__ jumps to PC relative offset if bit number uimm6 in register Xn is zero.

2. _Unconditional Branches:_
 * __B label__  jumps to PC relative offset.
 * __BL label__  jumps to PC relative offset, writing the address of the next sequential
instruction to register X30. Typically used for making function calls.

3. _Unconditional Branches to register:_
 * __BLR Xm__  unconditionally jumps to address in Xm, writing the address of the next
sequential instruction to register X30.
 * __BR Xm__  jumps to address in Xm.
 * __RET {Xm}__  jumps to register Xm.

We don't particular care about category three because, register states should not influenced by our hooking mechanism. However, category one and two are PC relative and therefore need to be updated if found in the preamble.

So, I wrote a function that updates the instructions. At the moment it only handles a subset of cases, specifically the `B.cond` and `B` instructions. The former is found in `objc_msgSend`.

```asm
__text:18DBB41C0  EXPORT _objc_msgSend
__text:18DBB41C0   _objc_msgSend 
__text:18DBB41C0     CMP             X0, #0
__text:18DBB41C4     B.LE            loc_18DBB4230
__text:18DBB41C8   loc_18DBB41C8
__text:18DBB41C8     LDR             X13, [X0]
__text:18DBB41CC     AND             X9, X13, #0x1FFFFFFF8
```

Now, I don't know about you but I don't particularly like to use complicated bit-wise operations to extract and modify data. It's kind of fun to do so, but it is also fragile and hard to read. Luckily for us, C was designed to work at such a low level. Each ARM64 instruction is four bytes and so we use bit fields in C structures to deal with them!

```c
typedef struct {
    uint32_t offset   : 26;
    uint32_t inst_num : 6;
} inst_b;
```

This is the unconditional PC relative jump.

```c
typedef struct {
    uint32_t condition: 4;
    uint32_t reserved : 1;
    uint32_t offset   : 19;
    uint32_t inst_num : 8;
} inst_b_cond;
```

And this one is the conditional PC relative jump. Back in the day, I wrote a plugin for IDAPro that gives the details of instruction under the cursor. It is called [IdaRef](https://github.com/nologic/idaref) and, for it, I produced an ASCII text file that has all the instruction and their bit fields clearly written out [3]. So the `B.cond` looks like this in memory. Notice right to left bit numbering.

```
31 30 29 28 27 26 25 24 23                                                              5 4 3            0
0  1  0  1  0  1  0  0                                      imm19                         0     cond
```

That is what we map our `inst_b_cond` structure to. Doing so allows us very easy abstraction over bit manipulation.

```c
void check_branches(s_jump_page* t_func, instruction_t* o_func) {
	...        
        instruction_t inst = t_func->inst[i];
        inst_b*       i_b      = (inst_b*)&inst;
        inst_b_cond*  i_b_cond = (inst_b_cond*)&inst;

        ...
        } else if(i_b_cond->inst_num == 0x54) {
            // conditional branch

            // save the original branch offset
            branch_offset = i_b_cond->offset;
            i_b_cond->offset = patch_offset;
        }


        ...
            // set jump point into the original function, 
            //   don't forget that it is PC relative
            t_func->jump_patch[use_jump_patch].jmp_addr = 
                 (address_t)( 
                 	((instruction_t*)o_func) 
                 	+ branch_offset + i);
        ...
```

With some important details removed, I'd like to highlight how we are checking the type of the instruction by overlaying the structure over the instruction integer and checking to see if the value of the instruction number is correct. If it is, then we use that pointer to read the offset and modify it to point to one of the _jump patches_. In the patch we place the absolute value of the address where the instruction would've jumped were it still back in the original `objc_msgSend` function. We do so for every branch instruction we might encounter.

Once the _jump page_ is constructed we insert the patch into `objc_msgSend` and complete the loop. The most important thing is, of course, that the hook function restores all the registers to the state just before CPU enters into `objc_msgSend` otherwise the whole thing will probably crash.

It is important to note that at the moment we require that the function to be hooked has to be at least four instructions long because that is the size of the patch. Other than that we don't even care if the target is a proper C function.

Do look through the implementation [4], I skip over some details that glues things together but the important bits that I mention should be enough to understand, in great detail, what is happening under the hood.

## Interpreting the call

Now that function hooking is done, it is time to level up and interpret the results. This is where we actually implement the `objc_trace` functionality. So, the patch to `objc_msgSend` actually redirects execution to one of our functions:

```c
__attribute__((naked))
id objc_msgSend_trace(id self, SEL op) {
    __asm__ __volatile__ (
        "stp fp, lr, [sp, #-16]!;\n"
        "mov fp, sp;\n"

        "sub    sp, sp, #(10*8 + 8*16);\n"
        "stp    q0, q1, [sp, #(0*16)];\n"
        "stp    q2, q3, [sp, #(2*16)];\n"
        "stp    q4, q5, [sp, #(4*16)];\n"
        "stp    q6, q7, [sp, #(6*16)];\n"
        "stp    x0, x1, [sp, #(8*16+0*8)];\n"
        "stp    x2, x3, [sp, #(8*16+2*8)];\n"
        "stp    x4, x5, [sp, #(8*16+4*8)];\n"
        "stp    x6, x7, [sp, #(8*16+6*8)];\n"
        "str    x8,     [sp, #(8*16+8*8)];\n"

        "BL _hook_callback64_pre;\n"
        "mov x9, x0;\n"

        // Restore all the parameter registers to the initial state.
        "ldp    q0, q1, [sp, #(0*16)];\n"
        "ldp    q2, q3, [sp, #(2*16)];\n"
        "ldp    q4, q5, [sp, #(4*16)];\n"
        "ldp    q6, q7, [sp, #(6*16)];\n"
        "ldp    x0, x1, [sp, #(8*16+0*8)];\n"
        "ldp    x2, x3, [sp, #(8*16+2*8)];\n"
        "ldp    x4, x5, [sp, #(8*16+4*8)];\n"
        "ldp    x6, x7, [sp, #(8*16+6*8)];\n"
        "ldr    x8,     [sp, #(8*16+8*8)];\n"
        // Restore the stack pointer, frame pointer and link register
        "mov    sp, fp;\n"
        "ldp    fp, lr, [sp], #16;\n"

        "BR x9;\n"       // call the jump page
    );
}
```

This function stores all calling convention relevant registers on the stack and calls our, `_hook_callback64_pre`, regular C function that can assume that it _is_ the `objc_msgSend` as it was called. In this function we can read parameters as if they were sent to the method call, this includes the class instance and the selector. Once `_hook_callback64_pre` returns our `objc_msgSend_trace` function will restore the registers and branch to the configured _jump page_ which will eventually branch back to the original call.

```c
void* hook_callback64_pre(id self, SEL op, void* a1, void* a2, void* a3, void* a4, void* a5) {
	// get the important bits: class, function
    char* classname = (char*) object_getClassName( self );
    if(classname == NULL) {
        classname = "nil";
    }
    
    char* opname = (char*) op;
    ...
    return original_msgSend;
}
```

Once we get into the `hook_callback64_pre` function, things get much simpler since we can use the _objc_ API to do our work. The only trick is the realization that the `SEL` type is actually a `char*` which we cast directly. This gives us the full selector. Counting colons will give us the count of parameters the method is expecting. When everything is done the output looks something like this:

```
iPhone:~ root# DYLD_INSERT_LIBRARIES=libobjc_trace.dylib /Applications/Maps.app/Maps
objc_msgSend function substrated from 0x197967bc0 to 0x10065b730, trampoline 0x100718000
000000009c158310: [NSStringROMKeySet_Embedded alloc ()]
000000009c158310: [NSSharedKeySet initialize ()]
000000009c158310: [NSStringROMKeySet_Embedded initialize ()]
000000009c158310: [NSStringROMKeySet_Embedded init ()]
000000009c158310: [NSStringROMKeySet_Embedded initWithKeys:count: (0x0 0x0 )]
000000009c158310: [NSStringROMKeySet_Embedded setSelect: (0x1 )]
000000009c158310: [NSStringROMKeySet_Embedded setC: (0x1 )]
000000009c158310: [NSStringROMKeySet_Embedded setM: (0xf6a )]
000000009c158310: [NSStringROMKeySet_Embedded setFactor: (0x7b5 )]
```

## Conclusion

We modify the `objc_msgSend` preamble to jump to our hook function. The hook function then does whatever and restores the CPU state. It then jumps into the _jump page_ which executes the possibly modified preamble instructions and jumps back into `objc_msgSend` to continue execution. We also maintain the original unmodified preamble for restoration when we need to remove the hook. Then we use the parameters that were sent to `objc_msgSend` to interpret the call and print out which method was called with which parameters.

As you can see using function hooking for making _objc_trace_ is but one use case. But this use case is incredibly useful for blackbox security testing. That is particularly true for initial discovery work of learning about the application.

-----
[1] [objc-msg-arm64.s](http://www.opensource.apple.com/source/objc4/objc4-647/runtime/Messengers.subproj/objc-msg-arm64.s)

[2] [ARM Reference Manual](https://www.element14.com/community/servlet/JiveServlet/previewBody/41836-102-1-229511/ARM.Reference_Manual.pdf)

[3] [ARM Instruction Details](https://raw.githubusercontent.com/nologic/x86doc/master/armv8_just_instructions.txt)

[4] [objc_trace.m](https://github.com/nologic/objc_trace/blob/master/objc_trace.m)

