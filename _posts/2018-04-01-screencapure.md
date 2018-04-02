---
layout: post
title: Who moved my pixels?!
---

Screen captures are super useful in my workflow and OS X makes it easy with just a few key combinations. However, I was really curious (worried) if someone could take a screen shot without my knowledge. So, I decided to figure out how that mechanism works and there was a way build malware to covertly steal these pixels. 

## Conclusion
Reversed the screencapture utility to find out how it uses the standard framework functions. Then traced the mechanism to the `WindowServer` and wrote a utility to covertly grab screens; `sandbox-exec` can't stop the screen gabs. Used `frida` to detect someone grabbing the screen pixels covertly. There is  malware, from 2013(!), that steals people's pixels: [macs.app](https://www.virustotal.com/en/file/6acd92d0dfe3e298d73b78a3dcc6d52ff4f85a70a9f2d0dcfe7ae4af2dd685cc/analysis/) [5]. As expected, there are multiple way to get the screenshots. This was known since, at least, [2011](https://twitter.com/patrickwardle/status/962803166323531777)!

Why does OS X allow any GUI/CUI program to capture the entire screen? There are dangerous security implications here! I propose to add mach message ID filtering to the sandbox configuration. `WindowServer` needs a mechanism to white list signed binaries that can execute privileged RPC functions. 

## How does the capture work?
If you wish to reproduce or follow the steps I've taken, linked below are the binaries that I used for the reverse engineering. The binaries are from MacOS High Sierra version 10.13.3.
 
 * [screencapture](../../../../resources/screencapture) (7a76ff24fbb9e2f1b1ca07e6d3f351114cf5af42)
 * [SkyLight](../../../../resources/SkyLight) (1481334038bd636ba0fc4c983c04e1787b33a5d5)

MacOS comes with a utility for capturing the screen pixels into an image file: `/usr/sbin/screencapture`. It is a useful utility and, I'm guessing, screencapture is what gets executed when I press the right key combinations on the desktop to take full or partial screenshots. So, I decided to reverse it and see how it actually does the capturing. Turns out it wasn't so complicated.

Starting the trace at the very beginning. This is where the command line arguments are processed; see `__text:100002640` and `__text:10000287E`. So, there is a good chance that this is where we should start tracing.

```Asm
__text:1000025B8 ; __int64 __fastcall start(int, char **)
__text:1000025B8                 public start
__text:1000025B8 start           proc near
...
__text:100002639  mov     qword ptr cs:xmmword_1000139A0, rcx
__text:100002640  lea     r15, aAbpidicmwwsosx 
                       ; "abPIdicmwWsoSxfrCMET:t:l:R:B:"
__text:100002647  lea     r12, dword_10000346C
...
__text:100002876  mov     edi, ebx        ; int
__text:100002878  mov     rsi, r14        ; char **
__text:10000287B  mov     rdx, r15        ; char *
__text:10000287E  call    _getopt
__text:100002883  lea     ecx, [rax-42h]
```

To be user friendly, the utility uses a shutter sound to indicate that a the screen has been captured. So, I turned up my speakers and started debugging! The sound would serve as guiding light to help narrow down the useful code.

```asm
__text:100002E67  jz      loc_100003130
__text:100002E6D  call    take_the_screenshot
__text:100002E72  jmp     loc_10000337B
```

Unfortunately, the sound is played very early in the process. At least, when I hear the sound, know I'm on the right path.

```
__text:100003D20 take_the_screenshot proc near
...
__text:100003D80  cmp     cs:byte_100012553, 0
__text:100003D87  jnz     short loc_100003D8E
__text:100003D89  call    playTheScreenshotSound
```

I know this is the sound playing function because it is essentially the wrapper to these calls (below). Also, because I can hear the sound after the functions finish execution!

```asm
__text:100007DC0  call    _AudioServicesSetProperty
__text:100007DC5  mov     edi, [rbx]
__text:100007DC7  call    _AudioServicesPlaySystemSound
```

Let's go back to the `take_the_screenshot` function (where the sound is played). Using a debugger, I step through a bunch of instructions (tedious!) when I notice a function that calls `_CGDisplayCreateImage` of the CoreGraphics framework. That looks promising!

```asm
__text:100004155  mov     [rsp+0E0h+var_E0], rax
__text:100004159  mov     edi, r12d
__text:10000415C  mov     rsi, r15
__text:10000415F  call    doCapture
__text:100004164  mov     r14, rax
__text:100004167  test    r14, r14
__text:10000416A  jz      loc_100004236
```

I named this function `doCapture` but at this point I'm not 100% certain if the name is accurate. However, without going into that function, I notice that the calls after `doCapture`, within the `take_the_screenshot` function, record an image to disk. I'm guessing the image being written to disk is the screenshot in question. Seems like a reasonable assumption, so I decided to follow that thread.

```asm
__text:10000418F  mov     rdi, r14        ; img
__text:100004192  mov     rsi, qword ptr [rbp+var_80]
__text:100004196  mov     rdx, r15
__text:100004199  call    writeImageToDisk
__text:10000419E  mov     rax, cs:qword_100012548
__text:1000041A5  add     rax, 0FFFFFFFFFFFFFFFEh
```

I named this function `writeImageToDisk`. And if you look inside, there are all sorts of references to recording images to a file on disk. Particularly interesting are the error messages:

```asm
__text:1000073D9  lea     rax, cfstr_YouDontHavePer 
                       ; "You dont have permission to save files \
                          in the location where screen shots are \
                          stored."
__text:1000073E0  mov     cs:qword_1000139F8, rax
__text:1000073E7  mov     rax, cs:___stderrp_ptr
__text:1000073EE  mov     rdi, [rax]      ; FILE *
__text:1000073F1  lea     rsi, aScreencaptur_6 
                      ; "screencapture: cannot write file to int"
```

And so, this is more support that `doCapture` is the function that does all the interesting bits. Let's keep the name and dig into it some more.

```asm
__text:1000052EA  call    _CGRectIsEmpty
__text:1000052EF  test    al, al
__text:1000052F1  jz      short loc_100005312
__text:1000052F3  mov     edi, r12d
__text:1000052F6  call    _CGDisplayCreateImage  ; Returns an \
                       image containing the contents of the   \
                       specified display
__text:1000052FB  mov     r15, rax
__text:1000052FE  lea     rbx, [rbp+var_C0]
__text:100005305  mov     rdi, rbx
__text:100005308  mov     esi, r12d
__text:10000530B  call    _CGDisplayBounds
__text:100005310  jmp     short loc_100005343
```

`CGDisplayCreateImage` looks promising, but at this point it could have number meanings. However, I'm a reverse engineer, I'm not afraid of going down a few rabbit holes! Well, this function is actually just a stub:

```asm
__stubs:10000BDE4 _CGDisplayCreateImage proc near  
                       ; CODE XREF: doCapture+49
__stubs:10000BDE4   jmp     cs:_CGDisplayCreateImage_ptr
__stubs:10000BDE4 _CGDisplayCreateImage endp
```

So, I go to the `CoreGraphics` (`_CG` gave that away!) framework and look for the function there:

```asm
__text:00000546A  public _CGDisplayCreateImage
__text:00000546A _CGDisplayCreateImage:

__text:00000546A  jz      short loc_5490
__text:00000546C  sbb     [rcx-75h], cl
__text:00000546F  sbb     [rax+39h], r9b
__text:00000546F
__text:000005473  db 0CEh, 75h, 1Bh, 49h, 8Bh
__text:000005478  dq 4820468B49202454h, \
                   88558B481675C239h, 181E998758B48h
__text:000005490
__text:000005490
__text:000005490 loc_5490: \
         ; CODE XREF: __text:_CGDisplayCreateImage
__text:000005490  add     [rcx-75h], cl
__text:000005493  and     [rcx-75h], r9b
__text:000005497  push    rsp
__text:000005498  and     al, 20h
__text:000005498
__text:00000549A  dw 4866h
__text:00000549C  db 0Fh
__text:00000549D
```

Ummm, what? That function doesn't look like it does anything useful! Worse, it does not look like it can even execute. What's going on here? Well, we go to our trusty LLDB debugger! Obviously, there is some sort of a runtime linking mechanism that replaces the CoreGraphics function with something else.


```sh
(lldb) bt
* thread #1, queue = 'com.apple.main-thread', stop reason = instruction step over
  * frame #0: 0x00007fff6e726ef9 SkyLight`SLSHWCaptureDesktop + 5517
    frame #1: 0x00007fff6e7294fa SkyLight`SLDisplayCreateImage + 34
    frame #2: 0x1000052fb screencapture`___lldb_unnamed_symbol17$$screencapture + 78
    frame #3: 0x100004164 screencapture`___lldb_unnamed_symbol12$$screencapture + 1092
    frame #4: 0x100002e72 screencapture`___lldb_unnamed_symbol8$$screencapture + 2234
    frame #5: 0x00007fff74579115 libdyld.dylib`start + 1
    frame #6: 0x00007fff74579115 libdyld.dylib`start + 1
```

Looking at the stack trace, it becomes obvious that the actual implementation used is actually the similarly named `SLDisplayCreateImage` function from the `SkyLight` private framework. So, what we saw in the CoreGraphics framework was some sort of a stub - makes sense, since there is non-executable content in there! Let's keep digging :-)

Looking at the assembly of `_SLDisplayCreateImage`, I can see that it is essentially a wrapper function for `_SLSHWCaptureDesktop`

```asm
__text:0001FB4D8  public _SLDisplayCreateImage
__text:0001FB4D8 _SLDisplayCreateImage proc near
...
__text:0001FB4ED  mov     r8d, 441h
__text:0001FB4F3  mov     ecx, eax
__text:0001FB4F5  call    _SLSHWCaptureDesktop
__text:0001FB4FA  mov     r14, rax
```

Intuitively, I'd expect that the actual contents for the screen pixels will be in a buffer of some service. So, I would not expect the user application to access that buffer directly in order to capture an image. That means there should be some sort of an IPC mechanism between the user application and the GUI service. On OS X, IPC means [MACH PORTS](https://developer.apple.com/library/content/documentation/Darwin/Conceptual/KernelProgramming/Mach/Mach.html) [0].

Below is the disassembly of the section of the function that sends a mach port message to the GUI Service in order to obtain the actual pixel content.

```asm
__text:0001F796C  public _SLSHWCaptureDesktop
__text:0001F796C _SLSHWCaptureDesktop proc near
...
__text:0001F832E  mov     rcx, cs:_NDR_record_ptr
__text:0001F8335  mov     rcx, [rcx]
__text:0001F8338  mov     [rbp-0A8h], rcx
__text:0001F833F  movaps  xmmword ptr [rbp+var_160], xmm1
__text:0001F8346  movups  [rbp+var_A0], xmm1
__text:0001F834D  movaps  xmmword ptr [rbp+var_190], xmm0
__text:0001F8354  movups  [rbp+var_90], xmm0
__text:0001F835B  mov     dword ptr [rbp+var_80], eax
__text:0001F835E  mov     eax, [rbp+var_1A4]
__text:0001F8364  mov     dword ptr [rbp+var_80+4], eax
__text:0001F8367  mov     [rbp+msg.msgh_bits], 1513h
__text:0001F8371  mov     eax, [rbp+remote_port]
__text:0001F8377  mov     [rbp+msg.msgh_remote_port], eax
__text:0001F837D  call    _mig_get_reply_port
__text:0001F8382  mov     [rbp+msg.msgh_local_port], eax
__text:0001F8388  mov     [rbp+msg.msgh_id], 732Ah
__text:0001F8392  mov     [rbp+msg.msgh_reserved], 0
__text:0001F839C  cmp     cs:_voucher_mach_msg_set_ptr, 0
__text:0001F83A4  jz      short loc_1F83B8
__text:0001F83A6  lea     rdi, [rbp+msg]
__text:0001F83AD  call    _voucher_mach_msg_set
__text:0001F83B2  mov     eax, [rbp+msg.msgh_local_port]
__text:0001F83B8
__text:0001F83B8 loc_1F83B8:
__text:0001F83B8  sub     rsp, 8
__text:0001F83BC  mov     esi, 3          ; option
__text:0001F83C1  mov     edx, 48h        ; send_size
__text:0001F83C6  mov     ecx, 136        ; rcv_size
__text:0001F83CB  xor     r9d, r9d        ; timeout
__text:0001F83CE  lea     rdi, [rbp+msg]  ; msg
__text:0001F83D5  mov     r8d, eax        ; rcv_name
__text:0001F83D8  push    0               ; notify
__text:0001F83DA  call    _mach_msg
```

Even though the assembly looks messy, the message is very simple and looks like this in psuedo-code:

```c
struct req_msg* rq_msg = (struct req_msg*)buffer;
    
rq_msg->header.msgh_bits = 0x00001513;
rq_msg->header.msgh_size = 0;
rq_msg->header.msgh_remote_port = session_port;
rq_msg->header.msgh_local_port = mig_get_reply_port();
rq_msg->header.msgh_voucher_port = 0;
rq_msg->header.msgh_id = 0x732A;
    
// NDR Record value:
rq_msg->ndr.int_rep = 1;
    
// x, y, width, height of the rectangle to capture
rq_msg->x = 0.0;
rq_msg->y = 0.0;
rq_msg->width = 1024.0;
rq_msg->height = 768.0;

rq_msg->display_id = 0x047400b0;
rq_msg->param5 = 0x00000441; // ¯\_(ツ)_/¯
    
// set the voucher
voucher_mach_msg_set(&rq_msg->header);

// request the pixels
if(mach_msg(&rq_msg->header, 0x3, 0x48, 0x88, 
             rq_msg->header.msgh_local_port, 0, 0) 
        != MACH_MSG_SUCCESS) {
   printf("Error sending mach message\n");
   exit(3);
}
```

This message executes an RPC function which take the arguments of the capture rectangle dimensions along with the display ID to capture from.

Tracing the `remote_port` variable, we can see that it is derived from a bootstrap call from within the `_SLSMainConnectionID` call.

```asm
__text:0001F796C  public _SLSHWCaptureDesktop
...
__text:0001F79A2  call    _SLSMainConnectionID
__text:0001F79A7  mov     edi, eax
__text:0001F79A9
__text:0001F79A9 loc_1F79A9:
__text:0001F79A9  call    _CGSGetConnectionPortById
__text:0001F79AE  mov     [rbp+remote_port], eax
__text:0001F79B4  test    eax, eax
```

It is a bit of a distraction to follow these steps in the same detail. However, there is a stack trace that looks like this:

```bash
_SLSHWCaptureDesktop
 > _SLSMainConnectionID
   > _SLSNewConnection
     > _SLSServerPort
       > _CGSLookupServerRootPort
         > _bootstrap_look_up2
```

Looking at the references to `_bootstrap_look_up2`, two names show up that look interesting:
* com.apple.windowserver.active
* com.apple.windowserver

We need to find out which service publishes these ports with these names. I wasn't quite sure how to do that directly, so I took a slightly different approach. Instead, I set a breakpoint on the `_mach_msg` and looked at the message header to obtain the remote port number:

```bash
(lldb) x/100wx $rdi
0x7ffeefbff640: 0x00131513 0x00000000 0x00002113 0x00000607
0x7ffeefbff650: 0x00001203 0x0000732a 0x00000000 0x00000001
(lldb) x/5i $rip
->  0x7fff6e7263da: callq  0x7fff6e7868ca 
                      ; symbol stub for: mach_msg
    0x7fff6e7263df: addq   $0x10, %rsp
    0x7fff6e7263e3: movl   %eax, %r14d
    0x7fff6e7263e6: leal   -0x10000002(%r14), %eax
    0x7fff6e7263ed: cmpl   $0xe, %eax
(lldb)
```

The remote port number is `0x00002113`. Then using `lsmp` command line tool, I can see that port `0x2113` belongs to the WindowServer process:

```bash
$ lsmp -a
0x00002113  0x7591764b  send  ... WindowServer

$ ps -ef | grep WindowServer
   88   201  /System/Library/PrivateFrameworks/ \
               SkyLight.framework/Resources/WindowServer -daemon
```

Loading the WindowServer in IDAPro, I can see that it uses the same framework at its core as the screencapture utility. That's kinda cool!

The WindowServer program is basically a simple wrapper for the functionality in the SkyLight library that I've been analyzing all this time. This makes life easier in many ways. So, I looked for a corresponding capture function - just thinking that one should exist by, perhaps, a slightly different name. Doing a simple text search, I found `_XHWCaptureDesktop`. Without hesitation, I attached the debugger and set a breakpoint. This is the resulting backtrace which looks super interesting!


```bash
* thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 2.1 3.1
  * frame #0: 0x00007fff544c3287 SkyLight`_XHWCaptureDesktop
    frame #1: 0x00007fff54638105 SkyLight`__connectionHandler_block_invoke + 87
    frame #2: 0x00007fff5468aa57 SkyLight`CGXHandleMessage + 107
    frame #3: 0x00007fff546373bf SkyLight`connectionHandler + 212
    frame #4: 0x00007fff546caf21 SkyLight`post_port_data + 235
    frame #5: 0x00007fff546cabfd SkyLight`run_one_server_pass + 949
    frame #6: 0x00007fff546ca7d3 SkyLight`CGXRunOneServicesPass + 460
    frame #7: 0x00007fff546cb2b9 SkyLight`SLXServer + 832
    frame #8: 0x000000010afdddde WindowServer`_mh_execute_header + 3550
    frame #9: 0x00007fff5a4ce115 libdyld.dylib`start + 1
```

Setting a breakpoint on `_XHWCaptureDesktop` and triggering a screencapture, we get a nice trace that confirms the theory! This is great because if we want to keep an eye on who takes screenshots on the system, we can just look for calls to this function!

## Detecting a screenshot

After analyzing the process of how the screencapture utility works, I became curious if there was a way to detect when my screen gets captured. One mechanism is to use the mdfind utility. This is what [Dave DeLong](https://github.com/davedelong/Demos/blob/master/ScreenShot%20Detector/ScreenShot%20Detector/ScreenShot_DetectorAppDelegate.m) [6] used in his method. However, it seems to depend on the capture utility to generate an image file and set the `kMDItemIsScreenCapture = 1` attribute within the file. Fairly certain that malware wouldn't do that. Well, unless you're developing KitM.A malware (see the Malware section)! This section is my exploration for how to perform detection of someone capturing the pixels off of my screen using the method reverse engineered in this article.

Detecting if some process has requested a screenshot is actually quite easy with the right tools. Using LLDB is too heavy and we don't really want to breakpoint a service that is being used. So, instead I decided to use [Frida](https://www.frida.re/) [1]. It is a great tool for dynamic analysis and uses techniques similar to those that would be applied by a production endpoint security tool.

```sh
dudes-Mac:~ dude$ sudo frida-trace  \
                    -a 'SkyLight!43287' WindowServer
Instrumenting functions...
sub_43287: Auto-generated handler at 
   "./__handlers__/SkyLight/sub_43287.js"
Started tracing 1 function. Press Ctrl+C to stop.
           /* TID 0x307 */
  6791 ms  sub_43287()
```

For some reason Frida would not resolve the `_XHWCaptureDesktop` function, however I was able to specify it by the offset into the dynamic library. The name resolution is probably some sort of a bug within Frida because all the other tools I've used (IDAPro, LLDB, nm) have resolved the symbol just fine.

Luckily for us, the mach message that contains the request from the client is passed in as an argument to the `_XHWCaptureDesktop` function. The pointer is passed in the `RDI` register.

```
* thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 1.1
    frame #0: 0x00007fff544c3287 SkyLight`_XHWCaptureDesktop
SkyLight`_XHWCaptureDesktop:
->  0x7fff544c3287 <+0>: pushq  %rbp
    0x7fff544c3288 <+1>: movq   %rsp, %rbp
    0x7fff544c328b <+4>: pushq  %r15
    0x7fff544c328d <+6>: pushq  %r14
Target 0: (WindowServer) stopped.
(lldb) x/10wx $rdi
0x7ffee4c12610: 0x00001112 0x00000048 0x000153ab 0x0001249b
0x7ffee4c12620: 0x00000000 0x0000732a 0x00000000 0x00000001
0x7ffee4c12630: 0x00000000 0x00000000
```

We can see that the message ID is `0x0000732a` (see the psuedocode above, in the screencapture reverse engineering section, for details) and the local port is `0x000153ab` that is the port this request was sent from. Let's use `lsmp` to track this port.

```
$ sudo lsmp -a
Process (4460) : screencapture
  name      ipc-object    rights     flags   boost  reqs  recv  send sonce oref  qlimit  msgcount  context            identifier  type
---------   ----------  ----------  -------- -----  ---- ----- ----- ----- ----  ------  --------  ------------------ ----------- ------------
0x00000103  0x56e57599  send        --------        ---            2                                                  0x00000000  TASK SELF (4460) screencapture
0x00000203  0x56e59519  recv        --------     0  ---      1               N        5         0  0x0000000000000000
0x00000307  0x56e59321  recv        --------     0  ---      1               N        5         0  0x0000000000000000
0x00000403  0x56e56e61  recv        --------     0  ---      1               N        5         0  0x0000000000000000
0x00000507  0x56e57a31  send        --------        ---            1                                                  0x00000000  THREAD (0x7faf5)
0x00000603  0x56e56729  recv        --------     0  ---      1           1   N        5         0  0x0000000000000000
                  +     send-once   --------        ---            1         <-                                       0x000153ab  (157) WindowServer
```

There's not really a good way to format the output of `lsmp`, but if you scroll to the side you will see that `0x000153ab` is connected to the WindowServer process. This is how we can derive the PID of the process that made the request.

Just to confirm, we can also see that the WindowServer process has a reference to this port as well:

```
Process (157) : WindowServer
  name      ipc-object    rights     flags   boost  reqs  recv  send sonce oref  qlimit  msgcount  context            identifier  type
---------   ----------  ----------  -------- -----  ---- ----- ----- ----- ----  ------  --------  ------------------ ----------- ------------
0x000153ab  0x56e56729  send-once   --------        ---                     ->        5         0  0x0000000000000000 0x00000603  (4460) screencapture
```

## Malware

In the conclusion, I mentioned that back in 2013 there was some malware that had screenshotting as one of its features. So, I obtained this sample. It is called [MAC.OSX.Backdoor.KitM.A](https://www.virustotal.com/en/file/6acd92d0dfe3e298d73b78a3dcc6d52ff4f85a70a9f2d0dcfe7ae4af2dd685cc/analysis/) by F-Secure and, by now, it is detected by everyone. You can download it here: [malware_KitM.zip](../../../../resources/malware_KitM.zip) Password `infect3d`.

```asm
__text:10000236F ; void __cdecl -[macpsAppDelegate getscreenshot]
                           (struct macpsAppDelegate *self, SEL)
__text:10000236F __macpsAppDelegate_getscreenshot_ proc near
...
__text:10000250F  lea     rdx, cfstr_UsrSbinScreenc 
                             ; "/usr/sbin/screencapture"
__text:100002516  mov     rdi, rbx
__text:100002519  call    cs:msgRef_setLaunchPath
                               ___objc_msgSend_fixup
__text:10000251F  lea     rsi, msgRef_arrayWithObjects
                               ___objc_msgSend_fixup
__text:100002526  lea     rdx, stru_100034A88 ; "-x"
__text:10000252D  lea     rcx, cfstr_T    ; "-T"
__text:100002534  lea     r8, cfstr_20    ; "20
```

Doing some quick reverse engineering, it's easy to see that the malware actually uses the `screencapture` utility that comes with the OS. It generates the screenshot images and uploads them somewhere. What's interesting is that it means these screen capture images could be found using the `mdfind kMDItemIsScreenCapture:1` command.

## Building the grabber

Let's say I was a [Russian Hacker](https://www.cnbc.com/2017/08/05/watch-this-russian-hacker-break-into-our-computer.html) and I wanted to covertly steal your pixels. Using the screencapture utility would work, but I don't want to give myself away by shouting the shutter sound. Luckily for me there's a super easy way of doing it myself! All I have to do is use the right libraries that are already on every OS X instance.

As it turns out, there is more than one way to grab screen pixels. In his blog, [Felix Krause](https://krausefx.com/blog/mac-privacy-sandboxed-mac-apps-can-take-screenshots) [7] uses the `CGWindowListCreateImage` function to capture the image. He goes a step further and actually sends the image through an OCR tool to extract the text. Cool! Below is my code for leveraging the same mechanism as the screencapture utility was revealed in the previous section.

```c
#include <CoreGraphics/CGDirectDisplay.h>
#include <ImageIO/CGImageDestination.h>
#include <CoreFoundation/CFURL.h>

void doCGCapture() {
    CGDirectDisplayID displays[256];
    uint32_t dispCount = 0;
    
    // get a list of all displays
    if(CGGetActiveDisplayList(256, displays, &dispCount)) {
        printf("Error getting display list\n");
        return;
    }
    
    // iterate screens and take the screenshots
    for(int i = 0; i < dispCount; i++) {
        CGDirectDisplayID dispId = displays[i];

        // get the raw pixels
        CGImageRef img = CGDisplayCreateImage(dispId);
        
        char path_str[1024];
        snprintf(path_str, 1023, "./image%d.png", i);
        
        // output file
        CFURLRef path = 
            CFURLCreateWithFileSystemPath(NULL, 
                   __CFStringMakeConstantString(path_str), 
                   kCFURLPOSIXPathStyle, false);
        
        // file/format to save pixels to
        CGImageDestinationRef destination = 
            CGImageDestinationCreateWithURL(
                   path, CFSTR("public.png"), 1, NULL); //[4]
        
        // add our captured pixels
        CGImageDestinationAddImage(destination, img, nil);
        
        // generate the image
        if (!CGImageDestinationFinalize(destination)) {
            printf("Failed to finalize\n");
        }
    }
}
```

Let's see how this code works in action:
<center>
<table border="0">
<tr border="0">
  <td border="0"><iframe width="420" height="315" src="https://www.youtube.com/embed/592HD1KWXnw" frameborder="0" allowfullscreen></iframe></td>
  <td border="0"><iframe width="420" height="315" src="https://www.youtube.com/embed/DtW9fF3gGOo" frameborder="0" allowfullscreen></iframe></td>
</tr>
</table>
</center>
<center></center>

The video on the left shows screen capturing via the command line or SSH. The video on the right shows the same thing by via a Cocoa App that is running from with in a very restrictive sandbox. The sandbox configuration that you would get if you get an application from the AppStore. Below is the screenshot ;) of the sandbox configuration that the app was build with. I know it was taking affect because I had to allow the App to store files in the Downloads folder otherwise it would get blocked by the sandbox.

![](../../../../resources/app_sandbox_config.png "Xcode Sandbox configuration")

No other permission was given to the App. By default the App pretty much cannot do anything on the system. This means that malware could come fully sandboxed and still steal your precious pixels!

As far as I could tell, pretty much any user and any process that has access (which is a lot!) to the GUI window server can request all the pixels. The closest way I found, as far as prevention, was to use the sandbox, via `sandbox-exec` command, mechanism with a strongly defined policy. 

```lisp
(deny mach-lookup
    (global-name "com.apple.windowserver.active"))
```

I'm not really an OS X expert, but I read some [blogs](https://reverse.put.as/wp-content/uploads/2011/09/Apple-Sandbox-Guide-v1.0.pdf) [2]. There I found that [OSXReverse](https://twitter.com/osxreverser) has developed a manual on how to configure the sandbox. The closest thing I could find was to prevent the process from looking up the WindowServer port via its name. However, this is not a practical mechanism because lots of applications will want to access the GUI and, more important, port numbers aren't that hard to bruteforce!

Instead, I really wish there was a mechanism to block mach messages with a specific message ID. For example, something like this:

```list
(deny mach-msg
    (mach-msg-id 0x732a))
```

Dare I say that we need a way to do deep message inspection and filtering on OS X? Ideally, there should be a mechanism where the WindowServer could white list the processes that are allowed to call certain RPC functions.

This way not every process would be allowed to steal pixels. Pixels that could contain private, confidential information like banking records, secret keys, or plans to the [Lockheed Martin F-35 Lightning II](https://en.wikipedia.org/wiki/Lockheed_Martin_F-35_Lightning_II) [3]!

---

0 - [Mach Overview](https://developer.apple.com/library/content/documentation/Darwin/Conceptual/KernelProgramming/Mach/Mach.html)

1 - [Frida](https://www.frida.re/)

2 - [Apple Sandbox Guide v1.0](https://reverse.put.as/wp-content/uploads/2011/09/Apple-Sandbox-Guide-v1.0.pdf)

3 - [Lockheed Martin F-35 Lightning II](https://en.wikipedia.org/wiki/Lockheed_Martin_F-35_Lightning_II)

4 - [System-Declared Uniform Type Identifiers](https://developer.apple.com/library/content/documentation/Miscellaneous/Reference/UTIRef/Articles/System-DeclaredUniformTypeIdentifiers.html#//apple_ref/doc/uid/TP40009259-SW1)

5 - [New Mac Malware Takes Screenshots And Uploads Them Without Permission](https://www.cultofmac.com/227658/new-mac-malware-takes-screenshots-and-uploads-them-without-permission/)

6 - [ScreenShot_DetectorAppDelegate.m](https://github.com/davedelong/Demos/blob/master/ScreenShot%20Detector/ScreenShot%20Detector/ScreenShot_DetectorAppDelegate.m)

7 - [Mac Privacy: Sandboxed Mac apps can record your screen at any time without you knowing](https://krausefx.com/blog/mac-privacy-sandboxed-mac-apps-can-take-screenshots)

8 - @patrickwardle: [...but we can't say we weren't 'warned' From 2011](https://twitter.com/patrickwardle/status/962803166323531777)