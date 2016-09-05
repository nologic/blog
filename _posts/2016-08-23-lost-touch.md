---
layout: post
title: Some folks lost their touch
draft: true
---

In an earlier post, I introduced CHAOTICMARCH - simple tool for simulating a user's interaction with an App for blackbox testing. The tool worked well and has helped me a lot with testing. However, all was not well. Every now and then, too often for my comfort, the tool's requests for touch were getting ignored. For example, CHAOTICMARCH would find a button and try to click it. The event would get logged and the little circle would show up on the screen. However, the App would ignore the request as if nothing happened. This become very frustrating to me and I was determined to find the root cause. Investigating this behavior took me down a deep rabbit hole. To find my way out, I built LLDB scripts, learned about iOS IPC and read lots of code. With this post, I would like to share my insights, lessons and scripts.

## Not so TL;DR;

iPhones are relatively small devices and, to provide a smooth user experience, Apple has to be really careful with task scheduling. Prioritized task queues are used for this. The queuing system is nicely explained in the [Run, RunLoop, Run](http://bou.io/RunRunLoopRun.html) blog post by Nicolas Bouilleaud. 

I had this missing touch problem to solve. After doing a lot of debugging and scripting, I eventually realize that the events were being ignored because the device was busy animating the fading circles. These circles are used by CHAOTICMARCH to show where the clicks have occurred. This theory was was validated by reordering drawing and clicking events.

In the process of analyzing and debugging, I built a sniffer for mach ports [1]. Then I found a mild bug in the simulate touch library that could be used to crash `backboardd` which will cause `SpringBoard` to restart.

The rest of this write up is about how I collected the mach messages and analyzed to confirm that the IPC mechanism is working as expected.

## Where is the touch?
It's important to note that the quick solution mentioned in TL;DR; was very not obvious initially. So, the first thing I did was to start reversing the `libsimulatetouch` library. My hope was that the more I learn about the library internals the more I will understand its properties. The source is in the [iolate/SimulateTouch](https://github.com/iolate/SimulateTouch) repository.

There is a "client" side, which is the application that wants to trigger an event - such as `/sbin/stouch`, and there is the "server" side. The server side is the injected DYLIB within the `backboardd` process that actually generates the HID events on behalf of the client. The client library is the `libsimulatetouch.dylib` - implemented by [STLibrary.mm](https://github.com/iolate/SimulateTouch/blob/master/STLibrary.mm) and the server is `SimulateTouch.dylib` mobile substrate library - implemented by [SimulateTouch.mm](https://github.com/iolate/SimulateTouch/blob/master/SimulateTouch.mm).

The communications between the client and the server are via [mach ports](http://www.nongnu.org/hurdextras/ipc_guide/mach_ipc_basic_concepts.html), the goto IPC mechanism of iOS and OS X. In concept, mach ports are very basic. A message is sent on a port object (something like a socket), a receiver on the other side responds on the same port. Very similar to UDP with an added benefit of being synchronous. When `mach_msg` function returns, the response will be in the client supplied response buffer. The basic `mach_msg` function is quite primitive and requires quite a lot of infrastructure to use properly. So, it's natural that there are several higher level IPC abstractions built on top of this mechanisms. Ian Beer does a great job summarizing them in his [Auditing and Exploiting
Apple IPC](https://thecyberwire.com/events/docs/IanBeer_JSS_Slides.pdf) talk.

Last thing about these mach messages. Services like the touch server will start listing ports which clients could look up via [bootstrap_lookup](http://opensource.apple.com//source/launchd/launchd-328/launchd/src/libbootstrap.c) function calls. They work similar to DNS where the client specifies a name and receives a numeric port value. The touch library specifically uses the `CFMessagePort` abstraction for IPC which is explained very nicely in the [Interprocess communication on iOS with Mach messages](http://ddeville.me/2015/02/interprocess-communication-on-ios-with-mach-messages) blog post by Damien DeVille. The libsimulatetouch client library uses the `CFMessagePortSendRequest` function to send messages to the server side.

## Sniffing the IPC
The problem we are trying solve is the mystery of why touch events have been disappearing. My first intuition was that perhaps these port messages were not getting to the server for some reason. Probably not because the kernel was messing up. But, likely because either the client wasn't sending the messages or the server wasn't processing them. So, I've decided to sniff the messages in the same way that I would with network traffic. After much googling, I found almost nothing for sniffing mach messages except for an old blog post about [mach_shark](http://blog.wuntee.sexy/CVE-2015-3795) which unfortunately was not released (and, on the last check the blog site was down -- here's a [web archive link](http://web.archive.org/web/20160413172707/http://blog.wuntee.sexy/CVE-2015-3795/)).

### What are we looking for?
What I'm looking for are the the messages that are sent to a port by name `kr.iolate.simulatetouch`. These messages have the following structure:

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

Super simple messages! Just 16 bytes long. As we mentioned earlier, each call to send a message returns with a response. The response for each of the client's request will be an integer which gives the path index. The path index is used to identify one continuous touch sequence. For example, if I request a touch DOWN, I will get an ID. Then I will use this ID to issue a touch UP which could be at a different location. The size of the response message is four bytes. The path index in necessary to support multi-finger capability i.e. a punch zoom.

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

The server which is a library that is injected into `backboardd` will start a local port and register a name to the port. Then it will use the CF abstraction to specify a callback function for the messages it receives. Once a message is received, the server will trigger the event then it will allocate a path index and return that number to the client. The client will be blocked until the message is returned. Quite a simple and common pattern for processing messages.

### Tangent: The bug
Let's go on a little tangent. While analyzing this code, I noticed that there is a bug in the path index allocation procedure. `getExtraIndexNumber` function works in a funny way. 

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

The function will get a random number between zero and thirteen, inclusive. If that path was already allocated, the function will attempt to get another number, randomly (!), by calling itself recursively. Who does that?! Maybe, this is just some remnants of old code.

Basically, this means that if I call a whole bunch of touch down events, I can allocate all fourteen paths and `getExtraIndexNumber` will be forced to run out of stack space as it looks for an unallocated path index. The impact is that `backboardd` will crash forcing `SpringBoard` to restart. I suppose you can call it a DoS attack, but the significance is so mild. In order to trigger this you'd have to be running within a process on a jailbroken device with the simulate touch library installed -- if that code is malicious, you've got bigger problems to deal with then some crashed GUI service.

### Finding the port
Moving on! The first thing we need to do is find the port number. Why do we need this number? Apps will usually use many ports. Particularly GUI libraries are heavy users. So, knowing the port number isolates your collection to the messages you're interested in. Also, everytime the App runs, port numbers will be different. Even though the name remains the same, when the ports are created, the numbers are allocated dynamically. So, we need to know the mapping at runtime.

I prefer minimally intrusive methods of introspection. For that reason I've chosen to use LLDB. Setting up a debugging session on a JailBroken iPhone is not trivial. However, I will leave it as an exercise to the reader to follow the setup instruction from the [iPhoneWiki](http://iphonedevwiki.net/index.php/Debugserver).

[LLDB](http://lldb.llvm.org/) is a really great debugger. One of my favourite features is its Python API interface. Using this interface we are able to script the debugger to automatically process memory in the context of a break point. Essentially, conveniently automating the manual work of analysing function inputs and output.

To find out name to port number mapping, we'll break point on the look up functions. There are three functions: `bootstrap_look_up` which is a wrapper for `bootstrap_look_up2`. There is also `bootstrap_look_up3` which looks to be a private function, but used by several libraries. So, we will try to break on the latter two.

```Python
# break on bootstrap_look_up2 start
bs_look2 = target.BreakpointCreateByName('bootstrap_look_up2', 
                        'libxpc.dylib')
bs_look2.SetScriptCallbackFunction(
                        'mach_sniff.rocketbootstrap_look_up')

# find the end of the function
for bp in bs_look2:
    insts = target.ReadInstructions(bp.GetAddress(), 100)
    first_ret = [i.GetAddress().GetLoadAddress(target) 
                  for i in insts if i.GetMnemonic(target) == 'ret']

    # Just look for the first RET instruction
    if(len(first_ret) > 0):
        bs_look2_end = target.BreakpointCreateByAddress(
                                                   first_ret[0])
        bs_look2_end.SetScriptCallbackFunction(
                        'mach_sniff.rocketbootstrap_look_up_end')

        print bs_look2_end
```

We don't need to break on `bootstrap_look_up` because `bootstrap_look_up2` is enough, the former is a wrapper for the latter.

```Python
# set on rocket if available, otherwise regular crashes.
bs_look3 = target.BreakpointCreateByName('rocketbootstrap_look_up', 
                        'librocketbootstrap.dylib')
if(not bs_look3.IsValid()):
    bs_look3 = target.BreakpointCreateByName('bootstrap_look_up3', 
                         'libxpc.dylib')

bs_look3.SetScriptCallbackFunction(
                        'mach_sniff.rocketbootstrap_look_up')

# look for the end of function
for bp in bs_look3:
    insts = target.ReadInstructions(bp.GetAddress(), 200)
    first_ret = [i.GetAddress().GetLoadAddress(target) 
                  for i in insts if i.GetMnemonic(target) == 'ret']

    if(len(first_ret) > 0):
        bs_look3_end = target.BreakpointCreateByAddress(
                                                  first_ret[0])
        bs_look3_end.SetScriptCallbackFunction(
                         'mach_sniff.rocketbootstrap_look_up_end')

        print bs_look3_end
```

We also want to break on `bootstrap_look_up3`, however something about how breakpoints work and how [`librocket_bootstrap`](https://github.com/rpetrich/RocketBootstrap) hooks the function clashes with catastrophic results. So, to handle this usecase we just support breaking on the rocket_bootstrap version which is `rocketbootstrap_look_up`.

In both case we set a handler function that will analyze the function parameters to extract the name and match with the user specified name. `mach_sniff.rocketbootstrap_look_up` is used for the start of the function and `mach_sniff.rocketbootstrap_look_up_end` for the end. The first will analyze the parameter and initiate the state. Then the latter will close the state and report the mapping to the user and follow on functions (i.e. sniffing on the messages).

Once the breakpoint for function begins and ends are set, it becomes pretty easy to track port numbers and names. When the look up is first called, registers `X1` and `X2` point to the name and the return value respectively. So, all we have to do is save off those values. We create a state at the state of the function and look it up at the end of the function to create the mapping.

```Python
look_up_states = {}

def rocketbootstrap_look_up(frame, bp_loc, dict):
    tid = thread.GetThreadID()

    # name of port to be looked up
    x1_name = long(registers[0].GetChildAtIndex(1).GetValue(), 16)

    # destination of the port number
    x2_ret_addr = long(registers[0].GetChildAtIndex(2).GetValue(), 16)

    error = lldb.SBError()
    port = process.ReadCStringFromMemory(x1_name, 256, error)
    if error.Success():
        if(port == port_name):
            # create state if it's the port we are looking for
            look_up_states[tid].append({
                'port': port,
                'ret_addr': x2_ret_addr
            })
    else:
        print 'port name error: ', error
```

At the end of the function we look up the state information by thread ID and match up the name with the port number.

```Python
def rocketbootstrap_look_up_end(frame, bp_loc, dict):
    tid = thread.GetThreadID()
    
    # logically confirms that the name matched to the port we want to sniff
    if(tid in look_up_states):
        state = look_up_states[tid].pop()

        error = lldb.SBError()

        # read port number from the return buffer
        port_id = process.ReadUnsignedFromMemory(state['ret_addr'], 4, error)

        if error.Success():
            print "FOUND PORT: %s=%x" % (state['port'], port_id)

            # start sniffing for messages on this port.
            if(len(look_up_states[tid]) == 0):
                start_sniff_port(debugger, port_id)
        else:
            print 'port id error: ', error
    else:
        print "end with no state"
```

Once we find the port name and number we are interested in, we initiate the sniffing mechanisms. Keeping the port number finding and sniffing of the messages is nice because it allows the user to potentially sniff on just a port number rather than name.

### Sniffing the mach messages
To find the messages we are interested in is the same basic process as finding ports. Initially, I wanted to get all the messages and then do post processing to filter out only the ones I'm interested in. However, breakpoints are expensive and the App would run beyond slow. So, it became necessary to only sniff on the ports of interest.

To be selective on the port we have to specify a breakpoint condition. This condition will chech that register `X0` contains our port number. Doing this is still expensive but it sped things up to a reasonable threshold.

```Python
def start_sniff_port(debugger, port_number):
    target = debugger.GetSelectedTarget()

    msg_bp = target.BreakpointCreateByName('mach_msg', 
                                 'libsystem_kernel.dylib')

    msg_bp.SetScriptCallbackFunction('mach_sniff.print_mach_msg')
    msg_bp.SetCondition("*(uint32_t*)($x0 + 8) == %d" % port_number)
```

Our breakpoint is set on the `mach_msg` function in `libsystem_kernel.dylib` library. This function is a wrapper for the actual system call.

```Python
def print_mach_msg(frame, bp_loc, dict):
    tid = thread.GetThreadID()

    x0_data = long(registers[0].GetChildAtIndex(0).GetValue(), 16)
    x1_opt = registers[0].GetChildAtIndex(1).GetValue()
    x2_len = long(registers[0].GetChildAtIndex(2).GetValue(), 16)
    x3_recv_len = long(registers[0].GetChildAtIndex(3).GetValue(), 16)
    x4_recv_name = long(registers[0].GetChildAtIndex(4).GetValue(), 16)
    x5_timeout = long(registers[0].GetChildAtIndex(5).GetValue(), 16)
    x5_notify = long(registers[0].GetChildAtIndex(6).GetValue(), 16)

    output = {
        'type': 'msg_send_start',
        'time': int(time.time()*1000),
        'frame': str(frame),
        'tid': tid,
        'send_msg_size': x2_len,
        'recv_msg_size': x3_recv_len,
        'msg_options': x1_opt,
        'rcv_name': x4_recv_name,
        'timeout': x5_timeout,
        'notify': x5_notify
    }

    data = None

    if(x2_len > 0):
        err = lldb.SBError()
        data = process.ReadMemory(x0_data, x2_len, err)

        output['msg'] = binascii.hexlify(data)

    output = json.dumps(output)
    output_file.write(output)
    output_file.write('\n')

    print output
```

On each message send for our port of interest we collect information from the registers and record the data into a while for later processing. In this case we just take the buffer at `X0` and read the amount of bytes specified in `X2` which is the length of the buffer. Other data is recorded as well but we'll find its usefulness sometime later.

Each entry in the output file will look like this:

```JSON
{"frame": "frame #0: 0x0000000197054c40 
           libsystem_kernel.dylib`mach_msg", 
 "tid": 135127, 
 "notify": 0, 
 "msg_options": "0x0000000000000011", 
 "rcv_name": 0, 
 "recv_msg_size": 0, 
 "send_msg_size": 76, 
 "timeout": 1000, 
 "time": 1471562568339, 
 "msg": "131500004c0000001b6c00000bc20000000
         00000010000000000000000000000000000
         000000000000000000f8f4f2f0010000000
         10000001000000001000000000000000080
         2f430000f041", 
 "type": "msg_send_start"}
```

In essence each line is a JSON record of the arguments `mach_msg` was called with. Kind of like `strace`.

## Making sense of it all
Recording the messages is just the first step. We also need to be able to understand them. Not surprisingly, they are layered in a similar way as network protocols. This is due to the various abstractions available to carry out IPC mechanisms. As I mentioned earlier, the usecase of the `libsimulatetouch` uses CF for their abstraction.

The first part is easy, it's just a standard message header for all mach messages:

```C
typedef struct
{
       mach_msg_bits_t          msgh_bits;
       mach_msg_size_t          msgh_size;
       mach_port_t       msgh_remote_port;
       mach_port_t        msgh_local_port;
       mach_msg_size_t      msgh_reserved;
       mach_msg_id_t              msgh_id;
} mach_msg_header_t;
```

This takes up 24 bytes of the message. Next is the header for [__CFMessagePortMachMessage](https://github.com/opensource-apple/CF/blob/master/CFMessagePort.c) which comes with a nice magic four bytes - 0xF0F2F4F8 - to help us identify the message easier.

```C
struct __CFMessagePortMachMessage {
    mach_msg_base_t           base;
    mach_msg_ool_descriptor_t  ool;

    struct innards {
        int32_t    magic;
        int32_t    msgid;
        int32_t   convid;
        int32_t byteslen;
        uint8_t bytes[0];
    } innards;
};
```

After that, it is just the message generated by the touch library. That message is 16 bytes:

```C
typedef struct {
    int type;       // STTouchType values (Up, down, move, etc)
    int index;      // pathIndex holder in message
    float point_x;  // X coordinate
    float point_y;  // Y coordinate
} STEvent;
```

All said and done, the entire message sent via `mach_msg` is 76 bytes long. Once parsed it looks something like this:

```JSON
{ '_payload': [ { 'ool_address': '0x0',
                  'ool_bytes': '0000000000000000',
                  'ool_copy': 0,
                  'ool_deallocate': 0,
                  'ool_pad1': 0,
                  'ool_size': '0x0',
                  'ool_type': 0},
                { 'inards_byteslen': '0x10',
                  'inards_convid': '0x12',
                  'inards_magic': '0xf0f2f4f8',
                  'inards_msgid': '0x1'},
                { 'index': 6, 
                  'point_x': 312.5, 
                  'point_y': 551.5, 
                  'type': 2}],
  'msgh_bits': 5395,
  'msgh_id': 1,
  'msgh_local_port': '0xc20b',
  'msgh_remote_port': '0x6c1b',
  'msgh_reserved': 0,
  'msgh_size': 76}
```

As you can see the coordinates and the type of touch are clearly visible and traceable. This is what I used to confirm that my touch events were sent as expected to the library.

## Conclusion
Debugging is a bit of an art form. It is so because one cannot see everything and the tools used for inspection are themselves faulty. So, it takes experience to know what to look for and how to interpret it. Much of the process is just validating the data flow, reassuring yourself that parts are working correctly. It is the hope that in that process one can learn more about the target which will help to narrow down on the problem. Here, I show my process for a specific usecase and provide the tools to build upon or learn from.


-----
[1] [machshark](https://github.com/nologic/machshark) - sniffing and parsing tools.
