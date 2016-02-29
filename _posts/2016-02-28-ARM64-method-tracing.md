---
layout: post
title: Tracing Objective-C method calls
draft: true
---

Linux has this great tool called `strace` on OSX there's a slightly worse tool called `dtrace`. Dtrace is not that bad, it gives pretty much everything you need. It is just not as nice as strace. However, on Linux there is also `ltrace` for library tracing. That is aguably more useful because you can see much more granular application activity. Unfortunately, there isn't such a tool on OSX. So, I decided to make - albeit a simpler version for now. I called it `objc_trace`.

Objc_trace's functionality is quite limited at the moment. It will print out the name of the method, the class and a list of parameters to the method. In the future it will be expanded to more things, however just knowing which method was called is enough for many debugging purposes.

## Something about the language

I won't spend too much time talking about [Objective-C](https://en.wikipedia.org/wiki/Objective-C), this subject has been covered pretty well by the hacker community. [Phrack Volume 0x0d, Issue 0x42, Phile #0x04 of 0x11](http://phrack.org/issues/66/4.html) is a great article covering verious internals of the language. However, I will scratch the surface to review some aspects that are useful for this context.

The language is incredibly dynamic. While still backwards compatible to C (or C++), most of the code is written using classes and methods. A class is exactly what you're thinking of. It can have static or instance methods or fields. For example, you might have a class `Book` with a method `Pages` that returns the contents. You might call it this way:

```objective-c
	Book* book = [[Book alloc] init];
	Page* pages = [book Pages];
```

The `alloc` function is a static method while the others (`init` and `Pages`) are dynamic. What actually happens is that the system sends messages to the object or the static class. The message contains the class name, the instance, the method name and any parameters. The the runtime will resolve which compiled function actually implements this method and call that.

If anything above doesn't make sense you might want to read the referenced Phrack article for more details.

Message passing is great, though there are all kinds of efficiency considerations in play. For example, methods that you call will eventually get cashed so that the resolution process occurs much faster. What's important to note is that there is some smoke and mirrors going on.

The system is actually not sending messages under the hood. What it is doing is routing the exection using a single library call: `objc_msgSend` [1]. This is due to how the concept of a message is implemented under the hood.

```objective-c
	id objc_msgSend(id self, SEL op, ...)
```

Let's take ourselves out of the Objective-C abstractions for a while and think about how things implemented in C. When a method is called the stack and the registers are configured for the `objc_msgSend` call. `id` type is kind of like a `void *` but restricted to Objective-C class instances. `SEL` type is actually `char*` type and refers to selectors, more specifically the methods names (which include parameters). For example, a method that takes two parameters will have a selector that might look something like this: `createGroup:withCapacity:`. Colons signal that there should be a parameter there. Really quite confusing but we won't dwell on that. 

The useful part is that a selector is a C-String that contains the method name and its named parameters. A non-obfuscating compiler does not remove them because the names are needed to resolve the implementing function.

Shockingly, the function that implements the method takes in two extra parameters ahead of the user defined parameters. Those are the `self` and the `op`. If you look at the disassembly, it looks something like this (taked from Damn Vulnerable iOS App):

```arm64
__text:0000000100005144
__text:0000000100005144 ; YapDatabaseViewState - (id)createGroup:(id) withCapacity:(uint64_t)
__text:0000000100005144 ; Attributes: bp-based frame
__text:0000000100005144
__text:0000000100005144 ; id __cdecl -[YapDatabaseViewState createGroup:withCapacity:]
                        ;         (struct YapDatabaseViewState *self, SEL, id, uint64_t)
__text:0000000100005144 __YapDatabaseViewState_createGroup_withCapacity__
```

Notice that the C function is called `__YapDatabaseViewState_createGroup_withCapacity__`, the method is called `createGroup` and the class is `YapDatabaseViewState`. It takes two parameters: an `id` and a `uint64_t`. However, it also takes a `struct YapDatabaseViewState *self` and a `SEL`. This signature essentially matches the signature of `objc_msgSend`, except that the latter has variadic parameters.

This is no mistake. The reason for this is that `objc_msgSend` will actually redirect execution to the implementing function but looking up the selector to function mapping within the class object. Once it finds the target it simply jumps there without having to readjust the parameter registers. This is why I refered to this a routing mechanism, rather than message passing. Of course, I say say that due to the implementation details, rather than the conceptual basis for what is happening here.

Quite smart actually, because this allows the language to be very dynamic in nature i.e. I can remap SEL to Function mapping and change the implementation of any particular method. This is also great for reverse engineering because this system retains a lot of the labeling information that the developer puts into the source code. I quite like that.

## The plan

Now that we've seen how Objective-C makes method calls, we notice that `objc_msgSend` becomes a choke point for all method calls. It is like the hub is a poorly setup setwork with many many users. So, in order to get a list of every method called all we have to do is watch this function. One way to do this is via a debugger such as LLDB or GDB. However, the trouble is that a debugger is fairly heavy and mostly interactive. It's not really good when you want to capture a run or watch the process to pin point a bug, the performance hit might be too much . For more offensive work, you can't embed one of those debuggers into a lite weight implant.

So, what we are going to do is hook the `objc_msgSend` function on an ARM64 iOS Objective-C program. This will allow us to specify a function to get called before `objc_msgSend` is actually executed. We will do this on a Jailbroken iPhone - so no security mechanism bypasses here, the Jailbreak takes care of all of that.

![alt text](../images/func_hooking.svg "Function hooking high level")

On the high level the hooking works something like this. `objc_msgSend` instructions are modified in the preamble to jump to another function. This other function will perform our custom tracing features, restore the CPU state and return to a jump table. The jump table is a custom piece of code that will execute the preamble instructions that we've overwritten and jump back to `objc_msgSend` to continue with normal exection.

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

The `s_jump_page` structure contains four instuctions that we overwrite (think back to the diagram at step 2). We also keep a backup of these instruction at the end of the struction. I will discuss why we do that later on. Then there are five structures called _jump patches_. These are special sets of instructions that will redirect the CPU to an arbirary location in memory. _Jump patches_ are also represented by a structure.

```c
typedef struct {
    instruction_t i1_ldr;
    instruction_t i2_br;
    address_t jmp_addr;
} s_jump_patch;
```

Using these structures we can build a very elegant and transparent mechanism for building dymanic code. All we have to do is create an inline assembly function in C and cast it to the structure.

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

This is ARM64 Assembly to load a 64-bit value from address `PC+8` then jump to it. The `.long` placeholders are places for target address. In order to use this we simply cast the code i.e. the `d_jump_patch` function pointer to the structure and set the value of the `jmp_addr` field. This is how we implement the function that generates the custom trampoline.

```c
void write_jmp_patch(void* buffer, void* dst) {
	// returns the pointer to d_jump_patch.
    s_jump_patch patch = *(jump_patch());

    patch.jmp_addr = (address_t)dst;

    *(s_jump_patch*)buffer = patch;
}
```

We take advantage of the C compiler automatically copying the entire size of the structure instead of using `memcpy`. In order to patch the original `objc_msgSend` function we use `write_jmp_patch` function and point it to the `hook` function. Of course, before we can do that we copy the orginal instructions to the _jump page_ for later execution and back up.

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

Now that we have saved the original instruction from `objc_msgSend` we have to be aware that we've copied four instructions. A lot can happen in four instructions, all sorts of decisions and branches. In particular I'm worried about branches because they are all relative. So, what we need to do is validate that `t_func->inst` doesn't have any branches. If it does, they will need to modified to preserve functionality.

This is why `s_jump_page` has five _jump patches_:

1. All four instructions are non branches, so the first _jump patch_ will automatically redirect exection to `objc_msgSend+16` (skipping the patch).
2. There are up to four branch instructions, so each of the _jump patches_ will be used to redirect to the appropriate offset into `objc_msgSend`.

Checking for branch instructions is a bit tricky. ARM64 is a RISC architecture and does not present the same veriety of instructions as, say, x86-64. But, there are still quite a few [2].

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

So, we wrote a function that does that. At the moment it only handles a subset of cases, specifically the `B.cond` and `B` instructions. The former is found in `objc_msgSend`.

Now, I don't know about you but I don't particularly like to use complicated bit-wise operations to extract and modify data. It kind of fun to do so, but it is also fragile and hard to read. Luckily for us, C was designed to work at such a low level. Each ARM64 instruction is four bytes and so we use bit fields in C structured to deal with them!

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

That is what we map our `inst_b_cond` structure. Doing so allows us very easy abstraction over bit manipulation.

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

With some important details removed, I'd like to highlight how we are checking the type of the instruction by overlaying the structure over the instruction integer and checking to see if the value of the instruction number is correct. If it is, then we use that pointer to read the offset and modify it point to one of the _jump patches_. In the patch we place the absolute value of the address where the instruction would've jumped were it still back in the orignal `objc_msgSend` function. We do so for every branch instuction we might encounter.

Once the _jump page_ is constructed we insert the patch into `objc_msgSend` and complete the loop. The most important thing is, of course, that the hook function restores all the registers to the state just before CPU enters into `objc_msgSend` otherwise the whole thing will probably crash.

It is important to note that at the moment we require that the function to be hooked can be anything, but it has to be at least four instructions long because that is the size of the patch.

Do look through the implementation [4], I skip over some details that glues things together but the important bits that I mention should be enough to understand, in great detail, what is happening under the hood.

## Conclusion

We modify the `objc_msgSend` preamble to jump to our hook function. The hook function then does whatever and restored the CPU state. It then jumps into the _jump page_ which executes the possibly modified preamble instuction and jumps back into `objc_msgSend` to continue execution. We also maintain the original unmodified preamble for restoration when we need to remove the hook.

-----
[1] [objc-msg-arm64.s](http://www.opensource.apple.com/source/objc4/objc4-647/runtime/Messengers.subproj/objc-msg-arm64.s)

[2] [ARM Reference Manual](https://www.element14.com/community/servlet/JiveServlet/previewBody/41836-102-1-229511/ARM.Reference_Manual.pdf)

[3] [ARM Instruction Details](https://raw.githubusercontent.com/nologic/x86doc/master/armv8_just_instructions.txt)

[4] [objc_trace.m](https://github.com/nologic/objc_trace/blob/master/objc_trace.m)

