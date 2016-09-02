---
layout: post
title: Some folks lost their touch
draft: true
---

In an earlier post, I introduced CHAOTICMARCH - simple tool for simulating a user's interaction with an app. It worked well and has helped me a lot with testing. However, all was not well. Every now and then, too often for my comform, the tool's requests for touch were getting ignored. For example, CHAOTICMARCH would find a button and try to click it. You'd see the logged events and the little circle show up on the screen where the event should have occured, but the app would ignore it as if nothing happened. This was very frustrating to me and I was determined to find the root cause. That took me down a pretty deep rabbit hole. To find my way out, I built LLDB scripts, learned about iOS IPC and read lots of code. With this post, I would like to share my insights and lessons.

## TL;DR;

iPhones are relatively small devices and, to provide a smooth user experience, Apple has to be really careful with task scheduling. Prioritized task queues are used for this. The queueing system is nicely explained in the [Run, RunLoop, Run](http://bou.io/RunRunLoopRun.html) blog post. I had this missing touch problem to solve, I've done a lot of debugging only to realize that the events were being ignored because the device was busy animating the fading circles. I use those circles to show where the clicks have occured.

In the process of analyzing and debugging, I built a sniffer for mach ports. Then I found a mild bug in the simulate touch library that could be used to crash `backboardd` which will cause `SpringBoard` to restart.

## Where is the touch?
It's important to note that the quick solution mentioned in TL;DR; was very not obvious to me. So, the first thing I did was to start reversing the `libsimulatetouch` library. My hope was that the more I learn about the library internals the more I will understand its properties. The source is in the [iolate/SimulateTouch](https://github.com/iolate/SimulateTouch) repository.

There is a "client" side, which is the application that wants to trigger an event - such as `/sbin/stouch`, and there is the "server" side. The server side is the injected DYLIB within the `backboardd` process that actually generates the HID event on behalf of the client. The client library is the `libsimulatetouch.dylib` - implemented by [STLibrary.mm](https://github.com/iolate/SimulateTouch/blob/master/STLibrary.mm) and the server is `SimulateTouch.dylib` mobile substrate library - implemented by [SimulateTouch.mm](https://github.com/iolate/SimulateTouch/blob/master/SimulateTouch.mm).

The communications between the client and the server as via [mach ports](http://www.nongnu.org/hurdextras/ipc_guide/mach_ipc_basic_concepts.html), the goto IPC mechanism of iOS. In concept, mach ports are very basic. A message is sent on a port object (something like a socket), a receiver on the other side responds on the same port. Very similar to UDP with an added benefit of having response when the sending function, `mach_msg`, returns. The basic `mach_msg` function is quite primitive and requires quite a lot of work to use. So, it's natural that there are several higher level IPC abstractions built on top of this mechanisms. Ian Beer does a great job summarizing them in his [Auditing and Exploiting
Apple IPC](https://thecyberwire.com/events/docs/IanBeer_JSS_Slides.pdf) talk.

Last thing about these mach messages. Services like the touch server will start listing ports which clicks can look up via [bootstrap_lookup](http://opensource.apple.com//source/launchd/launchd-328/launchd/src/libbootstrap.c) function calls. They work similar to DNS where the client specifies name and receives a numeric port value. The touch library specifically uses `CFMessagePort` abstraction for IPC which is explained very nicely by [Damien DeVille](http://ddeville.me/2015/02/interprocess-communication-on-ios-with-mach-messages). The libsimulatetouch client library uses the `CFMessagePortSendRequest` function to send messages to the server side.

## Sniffing the IPC
The problem we are trying solve is the mystery of why touch events have been disappearing. My first intuition was that perhaps these port messages were not getting to the server for some reason. So, I've decided to sniff them in the same way that I would with network traffic. After much googling, I found almost nothing for sniffing mach messages except for an old blog about [mach_shark](http://blog.wuntee.sexy/CVE-2015-3795) which unfortunately was not released (and, on the last check the blog site was down -- here's a [web archive link](http://web.archive.org/web/20160413172707/http://blog.wuntee.sexy/CVE-2015-3795/)).

### What are we looking for?
The messages that sent to a port by name `kr.iolate.simulatetouch`. These messages are very simple this following structure:

```C
typedef enum {  // sent as part of the 'type' field below
    STTouchMove = 0,
    STTouchDown,
    STTouchUp,

    // For these types, (int)point_x denotes button type
    STButtonUp,
    STButtonDown
} STTouchType;

typedef struct {
    int type;       // STTouchType values (Up, down, move, etc)
    int index;      // pathIndex holder in message
    float point_x;  // X coordinate
    float point_y;  // Y coordinate
} STEvent;
```

Super simple messages! Just 16 bytes long. As we mentioned earlier, each call to send a message returns with a response. The response for each of the client's request will be an integer which gives the path index. The path index is used to identify one continues touch sequence. For example, if I request a touch down, I will get an ID. Then I will use this ID to issue a touch up which could be at a different location. The size of the response message is four bytes.

The message processing pattern is very simple, [SimulateTouch.mm](https://github.com/iolate/SimulateTouch/blob/master/SimulateTouch.mm):

```C
static CFDataRef messageCallBack(CFMessagePortRef local, 
                                 SInt32 msgid, 
                                 CFDataRef cfData, 
                                 void *info)
{
   ...
   int pathIndex = touch->index;
   
   if (pathIndex == 0) {
        pathIndex = getExtraIndexNumber();
   }
   
   SimulateTouchEvent(port, pathIndex, touch->type, POINT(touch));
   
   ...             
   
   return (CFDataRef)[[NSData alloc] initWithBytes:&pathIndex 
                                     length:sizeof(pathIndex)];
   
   ...
}

...

CFMessagePortRef local = CFMessagePortCreateLocal(NULL, 
                            CFSTR(MACH_PORT_NAME), 
                            messageCallBack, NULL, NULL);

...

CFRunLoopSourceRef source = CFMessagePortCreateRunLoopSource(
                                  NULL, local, 0);
CFRunLoopAddSource(CFRunLoopGetCurrent(), 
                   source, kCFRunLoopDefaultMode);

...
```

The server which is a library that is injected into `backboardd` will start a local port and make it available by name. Then it will use the CF abstraction to specify a callback function for every message it receives. Once a messege is received, it will trigger the event, allocate a path index and return that number to the client. The client will be blocked until the message is returned. Quite a simple and common pattern for processing messages.

### Tangent: The bug
While analysing this code, I noticed that there is a bug in the path index allocation procedure. `getExtraIndexNumber` function works in a funny way. 

```C
static int getExtraIndexNumber()
{
    int r = arc4random()%14;
    r += 1; //except 0
    
    NSString* pin = Int2String(r);
    
    if ([[STTouches allKeys] containsObject:pin]) {
        return getExtraIndexNumber();
    }else{
        return r;
    }
}
```

The function will get a random number between zero and thirteen, inclusive. If that path was already allocated, it will attempt to get another number, randomly (!), again by calling itself recursively. Who does that?!

Basically, this means that if I call a whole bunch of touch down events, I can allocate all fourteen paths and `getExtraIndexNumber` will be forced to run out of stack space as it looks for an unallocated path index. The impact is that `backboardd` will crash forcing `SpringBoard` to restart. I suppose you can call it a DoS attack, but the significance is so mild. In order to trigger this you'd have to be running within a process on a jailbroken device -- if that code is malicious, you've got bigger problems to deal with.

### Finding the port
Moving on! The first thing we need to do is find the port number. Why do we need this number? Apps will usually use many ports. Particularly GUI libraries are heavy users. So, knowing the port number isolates your collection to the messages you're interested in. Also, everytime the App runs, port numbers will be different. Even though the name remains the same, when the ports are created, the numbers are allocated dynamically. So, we need to know the mapping at runtime.

I prefer minimally intrusive methods of introspection. For that reason I've chosen to use LLDB. Setting up a debugging session on a JailBroken iPhone is not trivial. However, I will leave it as an exercise to the reader to follow the setup instruction from the [iPhoneWiki](http://iphonedevwiki.net/index.php/Debugserver).

[LLDB](http://lldb.llvm.org/) is a really great debugger. One of my favourite features is its Python API interface. Using this interface we are able to script the debugger to automatically process memory in the context of a break point. Essentially, conveniently automating the manual work of analysing function inputs and output.

To find out name to port number mapping, we'll break point on the look up functions. There are three functions: `bootstrap_look_up` which is a wrapper for `bootstrap_look_up2`. There is also `bootstrap_look_up3` which looks to be a private function, but used by several libraries. So, we will try to break on the latter two.

```Python
    # break on bootstrap_look_up2 start
    bs_look2 = target.BreakpointCreateByName('bootstrap_look_up2', 'libxpc.dylib')
    bs_look2.SetScriptCallbackFunction('mach_sniff.rocketbootstrap_look_up')

    # find the end of the function
    for bp in bs_look2:
        insts = target.ReadInstructions(bp.GetAddress(), 100)
        first_ret = [i.GetAddress().GetLoadAddress(target) for i in insts if i.GetMnemonic(target) == 'ret']

        # Just look for the first RET instruction
        if(len(first_ret) > 0):
            bs_look2_end = target.BreakpointCreateByAddress(first_ret[0])
            bs_look2_end.SetScriptCallbackFunction('mach_sniff.rocketbootstrap_look_up_end')

            print bs_look2_end
```

We don't need to break on `bootstrap_look_up` because `bootstrap_look_up2` in enough.

```Python
    # set on rocket if available, otherwise regular crashes.
    bs_look3 = target.BreakpointCreateByName('rocketbootstrap_look_up', 'librocketbootstrap.dylib')
    if(not bs_look3.IsValid()):
        bs_look3 = target.BreakpointCreateByName('bootstrap_look_up3', 'libxpc.dylib')

    bs_look3.SetScriptCallbackFunction('mach_sniff.rocketbootstrap_look_up')

    # look for the end of function
    for bp in bs_look3:
        insts = target.ReadInstructions(bp.GetAddress(), 200)
        first_ret = [i.GetAddress().GetLoadAddress(target) for i in insts if i.GetMnemonic(target) == 'ret']

        if(len(first_ret) > 0):
            bs_look3_end = target.BreakpointCreateByAddress(first_ret[0])
            bs_look3_end.SetScriptCallbackFunction('mach_sniff.rocketbootstrap_look_up_end')

            print bs_look3_end
```

We also want to break on `bootstrap_look_up3`, however something about how breakpoints work and how [`librocket_bootstrap`](http://iphonedevwiki.net/index.php/RocketBootstrap) hooks the function clashes with catastrophic results. So, to handle this usecase we just support breaking on the rocket_bootstrap version which is `rocketbootstrap_look_up`.

In both case we set a handler function that will analyze the function parameters to extract the name and match with the user specified name.



-----

