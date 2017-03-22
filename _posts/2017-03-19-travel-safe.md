---
layout: post
title: Protecting the digital nomad
draft: true
---

Digital nomads, driven by the expanding Internet bandwidth and availability, are growing in numbers. There are open communities like the Subreddit [/r/digitalnomad](https://www.reddit.com/r/digitalnomad/) and others are commercial like the [Digital Nomad Community](https://digitalnomadcommunity.net/). However, from the [Cyber hygiene](https://en.wikipedia.org/wiki/Cyber_hygiene) point of view, bouncing around like that can be about as safe as unprotected sex. In this post, I'd like to explore the security of one device that aims to protect the traveler's meatspace to cyberspace bridge. The device is the *HooToo Travel Mate 06 (TM-06)* travel router - it is a cute little device but provides loads of security fun!

# Motivation
The community of digital nomads is growing in addition to an already large number of business/vacation travelers around the world. Apparently, the community is on its way to [one billion](https://levels.io/future-of-digital-nomads/) in numbers. However, I'm more interested on the security side. Their security needs are quite demanding because they have to touch many networks/devices with questionable security hygiene. At [Blackhat 2016](http://www.blackhat.com/us-16/briefings.html#airbnbeware-short-term-rentals-long-term-pwnage), there was a talk on Internet safety in AirBnB’s and similar rentals. The speaker showed us how risky it can be to move between networks of differing standards. As this talk points out, there is a similar issue with public Café Wi-Fi’s. The wireless networks from one location to another vary greatly, mostly within the category of being vulnerable, exposing guests and hosts to malware. That piqued my interest and initiated this research.

Looking for a solution, I discovered the concept of a travel router. Basically, a MiFi but without the SIM card and some additional features. A search on amazon returned well over a thousand of results - ranging in fitness to the search criteria. Taking price and function into account, I zeroed in on the HooToo TM-06 (the device). Its functions include Wi-Fi extension, Wi-Fi to Ethernet bridging and Hot Spot creation. However, security is one of the selling points: "create your own secure Wi-Fi network," they said. I took this to mean that I can create a network more secure than what I bridge to in a Café, AirBnB or a hotel. At the very least, I could have an additional layer of protection such as what I could get from a NAT or a good firewall. Naturally, I wanted to _thoroughly_ check if this security claim was true.

# Previous work
There was some initial work done on HooToo devices, including the previous versions of the TM-06, by [chorankates](https://github.com/chorankates/h4ck/tree/master/hootoo). Also, [Smith](https://www.exploit-db.com/exploits/38081/) published XSRF exploits which remain unpatched. However, I wanted to see if I could get more out of it.

While the device seems to be popular on the Amazon, I don't really see them around much. So they are not mainstream popular, not like an iPhone, but there are still enough out there to make for a useful target and pose some real dangers. Unfortunately, being below the radar also means that the device has not received much scrutiny from the security community to ensure the devices are safe to use.

# Let's get to work!
The device is configurable via a web interface and it exposes a whole bunch of TCP ports to support its various features.

![](../../../../images/hootoo_login_page.png "Login page")

__Figure 1:__ Login page

By default, the device doesn’t have a password set on the admin user in the web interface. The user is expected to change it upon initial setup. This is not bad in itself but the device should really require the user to set the password after initial login. The WebUI itself doesn't provide a lot of rich features - it is a simple, to the point, UI. What you'll find there are some basic Wi-Fi settings, MAC spoofing, access to media storage and network configurations. Obviously, an attacker getting access to such things would be bad but not too damaging.

![](../../../../images/hootoo_internet_page.png "Configuring the Wi-Fi Bridge")

__Figure 2:__ Login page

Of course, all HTTP interactions are unsecured. There's no way of configuring TLS for Admin interface. As long as you configure WPA for your wireless network then that should be OK, right? I guess, it just depends on how much you trust the people you allow to connect to the device with you. Personally, I would've preferred to have some TLS, not like encryption takes so many resources to run for one user. This is a perfect case where I'd gave away some performance for much more security.

Next, we connect to the device's local Wi-Fi and do a full nmap scan:
```
  $ nmap 192.168.1.1 -p 0-65535
  Starting Nmap 7.31 ( https://nmap.org ) at 2016-12-07 08:35 EST
  Strange read error from 192.168.1.1 (49 - 'Can't assign requested address')
  Nmap scan report for 192.168.1.1
  Host is up (0.0049s latency).
  Not shown: 65531 closed ports
  PORT     STATE    SERVICE
  0/tcp    filtered unknown
  80/tcp   open     http
  81/tcp   open     hosts2-ns
  5880/tcp open     unknown
  8201/tcp open     trivnet2
```
Some interesting things there. I always enjoy seeing 'weird' looking ports that open for business. Not quite sure what to do with them yet but I imagine they have something to do with the various services (such as samba and DLNA Services) that the device provides. I was, however, disappointed that there are no remote shell ports to be found, such as ssh or telnet. That is especially because telnet was discovered during analysis of older versions, by chorankates. I guess HooToo did some enhancements since then.

# The firmware
Next, I'd like to look at the firmware and see what kind of interesting things we could discover there. After a little bit of googling, I found that it's possible to update the device with new firmware found on the [HooToo support](http://www.hootoo.com/downloads-HT-TM06.html) page. The update process is to upload the update file via the authenticated web interface. Finding an update file like this is exciting because it means we get to peek inside the code that is executing on our device.

```
mike@ubuntu:~/$ wget http://www.hootoo.com/media/downloads/HT-TM06-2.000.038.zip
--2017-03-19 20:20:36--  http://www.hootoo.com/media/downloads/HT-TM06-2.000.038.zip
HTTP request sent, awaiting response... 200 OK
Length: 26610217 (25M) [application/zip]
Saving to: ‘HT-TM06-2.000.038.zip’

100%[=====================================================================>] 26,610,217  8.60MB/s   in 3.0s

2017-03-19 20:20:39 (8.60 MB/s) - ‘HT-TM06-2.000.038.zip’ saved [26610217/26610217]

mike@ubuntu:~/$ unzip HT-TM06-2.000.038.zip
Archive:  HT-TM06-2.000.038.zip
  inflating: Change log.txt
  inflating: HT-TM06-Fix bug-2.000.038
  inflating: HT-TM06-2.000.038.bin
  inflating: HT-TM06-2.000.038
```

I'm not quite sure why, but the update package included the same file thrice. Each with a different name:

```
mike@ubuntu:~/$ md5sum *
8e99584da7cbb946695669f588b81430  HT-TM06-2.000.038
8e99584da7cbb946695669f588b81430  HT-TM06-2.000.038.bin
8e99584da7cbb946695669f588b81430  HT-TM06-Fix bug-2.000.038
```

Looking at the binary, we find that it is actually just a bash shell script:

```bash
mike@ubuntu:~/$ head -3 HT-TM06-2.000.038
#!/bin/sh
# constant
CRCSUM=3448271509
```

The first thing that stands out is the fact that there is no cryptographic signature to be found. So there's no way to verify authenticity. The only thing we get is a CRC checksum which is clearly not a security mechanism.

Next, we find this little section in the script:

```bash
# untar
echo "unzip firmware package"
...
tail -n +$SKIP $0 > $FWPT/upfs.gz
```

The script executes a tail command on itself where it skips `SKIP` number of lines. `SKIP` is defined to be `263`. The reference to firmware is encouraging and curious, so let's run this command and see what happens.

```
mike@ubuntu:~/$ tail -n +263 HT-TM06-2.000.038 > upfs.gz
mike@ubuntu:~/$ file upfs.gz
upfs.gz: gzip compressed data, was "initrdup", from Unix, last modified: Tue Feb 14 00:36:14 2017, max compression
```

Cool! That seems to have worked and given us a valid gzip file.

```
mike@ubuntu:~/$ gunzip upfs.gz
mike@ubuntu:~/$ file upfs
upfs: Linux rev 1.0 ext2 filesystem data, UUID=0339a2bf-8f6e-47d0-a3fd-4c4282c9d522
```

Uncompressing the gzip, we see that it is an `ext2` filesystem. Now, I'm truly excited because we can mount something :-)

```
mike@ubuntu:~/$ sudo mount -o loop upfs upfs.mount/
mike@ubuntu:~/$ ls upfs.mount/
bin  boot  config  dev  etc  firmware  lib  mnt  proc  sys  update.sh  var
```

We get lots more fun things to play with. That `update.sh` file and the `firmware` directory are the first targets - specifically, `firmware` looks most interesting. So, let's keep unwrapping this package!

```
mike@ubuntu:~/upfs.mount$ file firmware/*
firmware/bootloader:    data
firmware/firmware.conf: ASCII text
firmware/kernel:        u-boot legacy uImage, Linux Kernel Image, Linux/MIPS, OS Kernel Image (lzma), 1544372 bytes, Wed Oct 28 00:25:02 2015, Load Address: 0x80000000, Entry Point: 0x8000C2F0, Header CRC: 0x14F420EC, Data CRC: 0x54A3AFE8
firmware/rootfs:        Squashfs filesystem, little endian, version 4.0, 5566433 bytes, 1105 inodes, blocksize: 131072 bytes, created: Tue Feb 14 00:36:10 2017
```

`rootfs` looks promising because it is a *Squashfs* filesystem, so this file probably lands up on the flash drive of the device. Looking at the kernel we can also get some information about when it as built and the kind of architecture we should expect. So, let's mount the filesystem and peek inside.

```
mike@ubuntu:~/blog_firmware$ tree -h --dirsfirst -L 3 --filelimit 20 ./rootfs.mount/
./rootfs.mount/
├── [1.1K]  bin [81 entries exceeds filelimit, not opening dir]
├── [  26]  boot
│   └── [   3]  tmp
├── [   3]  data
├── [ 218]  dev
├── [1.1K]  etc [66 entries exceeds filelimit, not opening dir]
├── [  26]  etc_ro
│   └── [  28]  ppp
│       └── [ 363]  ip-up
├── [   3]  home
├── [1.3K]  lib [63 entries exceeds filelimit, not opening dir]
├── [   3]  media
├── [   3]  mnt
├── [   3]  opt
├── [   3]  proc
├── [ 835]  sbin [48 entries exceeds filelimit, not opening dir]
├── [   3]  sys
├── [   3]  tmp
├── [ 119]  usr
│   ├── [ 550]  bin [42 entries exceeds filelimit, not opening dir]
│   ├── [   3]  codepages
│   ├── [  42]  lib
│   │   ├── [ 208]  fileserv
│   │   └── [  34]  ppp
│   ├── [  44]  local
│   │   ├── [   3]  fileserv
│   │   └── [  26]  samba
│   ├── [1008]  sbin [60 entries exceeds filelimit, not opening dir]
│   ├── [  31]  share
│   │   └── [1.7K]  zoneinfo
│   └── [310K]  dev.tar
├── [ 111]  var
│   ├── [   3]  cache
│   ├── [   3]  lock
│   ├── [   3]  locks
│   ├── [   3]  log
│   ├── [   3]  logs
│   ├── [   3]  run
│   ├── [   3]  state
│   └── [   3]  tmp
└── [ 139]  www
    ├── [ 192]  app
    │   ├── [  97]  explorer
    │   ├── [  91]  information
    │   ├── [ 189]  network
    │   ├── [ 150]  services
    │   ├── [ 105]  system
    │   ├── [ 109]  user
    │   ├── [ 125]  wizard
    │   ├── [3.8K]  main.html
    │   ├── [2.5K]  metro.html
    │   ├── [1.9K]  set.html
    │   └── [1.3K]  wifiapi.html
    ├── [   3]  firmware
    ├── [ 158]  lang
    │   ├── [   0]  com.err
    │   ├── [  12]  dldlink.csp
    │   ├── [  13]  error.csp
    │   ├── [  12]  header.html
    │   ├── [  12]  index.csp
    │   ├── [  14]  protocol.csp
    │   ├── [  12]  sysfirm.csp
    │   └── [  12]  tail.html
    ├── [  34]  miniyun
    │   └── [ 381]  miniyun.htm
    ├── [  69]  script
    │   ├── [ 224]  app
    │   ├── [ 236]  lge
    │   ├── [3.8K]  config.js
    │   └── [ 98K]  core.js
    ├── [  57]  themes
    │   ├── [ 192]  default
    │   └── [ 209]  HT-TM06
    └── [2.0K]  index.html

59 directories, 35 files
```

There is nothing really that is out of the ordinary. Looks like a small, possibly custom, distribution of Linux for a MIPS embedded system. On the [support page](http://www.hootoo.com/hootoo-tripmate-ht-tm06-wireless-router.html), we see that the device's chipset is MTK 7620. With this information we can find the [datasheet](https://wiki.microduino.cc/images/3/34/MT7620_Datasheet.pdf) and the CPU instruction set manual for the [MIPS32 24K](https://people.freebsd.org/~adrian/mips/MD00343-2B-24K-SUM-03.11.pdf) Processor. This will come handy in the future.

```
mike@ubuntu:~/$ cat ./rootfs.mount/etc/passwd
root:$1$yikWMdhq$cIUPc1dKQYHkkKkiVpM/v/:0:0:root:/root:/bin/sh
...
```

It only took about two days of [_john the ripper_](http://www.openwall.com/john/) on a reasonably priced AWS instance. The password was discovered by brute force: `20080826`. What's sad is that we have no where to use this password on. There's no login shell and the root user does not work via the web interface. Also, I couldn't authenticate by directly sending the `root` login request using [burp](https://portswigger.net/burp/) - so, the username enforcement is happening on the device. This is a good sign, otherwise we'd have a nice back door that no one would likely check for.

For this write up, we'll stop here with the firmware analysis. There's certainly more to do. But for now, we have all the files that we need for further specialized branches of analysis.

# Getting a debugger
So far, we've discovered some useful things about the device: the firmware, some unfixed issues and its architecture. However, nothing terrible and, as I've eluded to earlier, we really want to get some execution on the device. Ideally, we want to crack in but until then let's see if we can use semi-normal methods.

Looking at our analysis so far, we notice that the firmware is not signed and it is a simple shell script. So, let's build our own update! :-) Also, we notice that in the previous analysis, by [chorankates](https://github.com/chorankates/h4ck/tree/master/hootoo), the earlier versions of the device had port 23 (telnet) open. So, I would guess that this functionality was disabled rather than removed.

```
mike@ubuntu:~/rootfs.mount$ find ./ -iname '*telnet*'
./etc/checktelnetflag
./etc/init.d/opentelnet.sh
./etc/telnetpasswd
./etc/telnetshadow
./usr/sbin/telnetd
mike@ubuntu:~/rootfs.mount$ cat ./etc/init.d/opentelnet.sh
#!/bin/sh
if [ ! -f /etc/telnetflag ]; then
	touch /etc/telnetflag
       sed -i "s|:/root:/sbin/nologin|:/root:/bin/sh|" /etc/passwd
	telnetd &
	/etc/init.d/etcsync
fi
```

A quick search reveals that telnet is, indeed, available and can be started via the `opentelnet.sh` script. What we'll do is attempt to execute this command via our own firmware update package.

The update mechanism is accessible after the `admin` user has logged in on this URL: http://192.168.1.1/app/system/firmware.html.

![](../../../../images/hootoo_update_page.png "Uploading new firmware")

My first attempt was to upload a basic shell script:

```bash
#!/bin/sh
/bin/sh /etc/init.d/opentelnet.sh

exit 1
```

I wanted to return an error, so that the system didn't decide to irreversibly change anything else and possibly brick the device. Unfortunately, that did not work. Obviously, I got no explanation. Further analyzing the official update package, we notice that the update usually comes with a CRC checksum. There is a check in the official firmware update that looks like this:

```bash
crcsum=`sed '1,3d' $0|cksum|sed -e 's/ /Z/' -e 's/   /Z/'|cut -dZ -f1`
[ "$crcsum" != "$CRCSUM" ] && {
        echo "firmware crc error!"
        upstat 2 1
        [ -f /tmp/update_flag ] && exit 0	
        exit 1
}
echo "firmware crc success!"
```

It was a little confusing why the failure occurred even though the check looks to be self enforced. What I realized later, is that the device will actually perform it's own CRC validation before letting the script execute. However, the process is the same.

Using my Mac Book Pro, I generated a check sum using the same command that was found in the official update. Notice that I'm using an older version of the firmware than the one I mentioned above. This is because at the time of this research version 2.000.030 was the latest. So far, such details are not relevant to the work in this writeup.

```
$ sed '1,3d' fw-7620-WiFiDGRJ-HooToo-633-HT-TM06-2.000.030 \
  |cksum|sed -e 's/ /Z/' -e 's/   /Z/'|cut -dZ -f1
3784598516
```

D'oh! It doesn't match! The number in the firmware file is `3587589093`. That's weird! This was a real head scratcher for a while because I really wanted to be able to generate a CRC number that matches what the device expects. After a few hours of unproductive search, I decided to try it on my Ubuntu VM.

```
mike@ubuntu:~$ sed '1,3d' fw-7620-WiFiDGRJ-HooToo-633-HT-TM06-2.000.030 \
              |cksum|sed -e 's/ /Z/' -e 's/   /Z/'|cut -dZ -f1
3587589093
```

Worked! I still don't know what the deal is - I'm sure there is a simple explanation. It looks like the `cksum` command on Linux uses a different algorithm compared to the on OS X. Probably should have done this sooner given that the device runs a version of Linux. Lessons learned!

With this information, I constructed another shell script with a proper CRC checksum this time:

```bash
#!/bin/sh
# constant
CRCSUM=2787560248
VENDOR=HooToo
PRODUCTLINE=WiFiDGRJ
SKIP=263
TARGET_OS="linux"
TARGET_ARCH="arm"
DEVICE_TYPE=HT-TM06
VERSION=2000030
CPU=7620

/bin/sh /etc/init.d/opentelnet.sh

exit 1
```

Those other lines are a copy/paste by product, since the CRC was already generates I didn't want to take them out. Upon uploading this as a firmware update, the device gave me an error. However, doing a network scan, I saw that telnet was open! This means that the error was generated by the `exit 1`, rather than by incompatible firmware.

```
$ nmap 192.168.1.1
Nmap scan report for 192.168.1.1
Host is up (0.0092s latency).
PORT   STATE SERVICE
23/tcp open  telnet
80/tcp open  http
81/tcp open  hosts2-ns

Nmap done: 1 IP address (1 host up) scanned in 0.19 seconds
```

The custom update enabled us to login using the cracked root password:

```
$ telnet 192.168.1.1
Connected to 192.168.1.1.
Escape character is '^]'.

HT-TM06 login: root
Password:
login: can't chdir to home directory '/root'
# ls
bin     data    etc     home    media   opt     sbin    tmp     var
boot    dev     etc_ro  lib     mnt     proc    sys     usr     www
# Connection closed by foreign host.
```

We are in business! Getting a command shell on an embedded device is so exciting :-) But, let's move on. The title of this section is 'Getting a debugger' and that is what I want. GDB comes to mind, however, I do not find it on the device. This means we will have to find a version that runs on MIPS. After some googling, I found that [Rapid7](https://github.com/rapid7/embedded-tools) has actually published a version of the GDB server that runs on MIPS. Although, we have a terminal session on the device, there's not really a good way of uploading files to it. However, it does automatically mount USB storage devices which is super convenient.

We attach to a process like so:

```
# /data/UsbDisk1/Volume1/gdbserver.mipsle --attach *:9999 7344
Attached; pid = 7344
Listening on port 9999
```

Then, we use gdb-multiarch to connect to the server. I haven't been able to get that to work on OS X, so I used the easy way on Ubuntu:

```
mike@ubuntu:~$ gdb-multiarch
(gdb) target remote 192.168.1.1:9999
Remote debugging using 192.168.1.1:9999
0x2bb5595c in ?? ()
(gdb) i r
          zero       at       v0       v1       a0       a1       a2       a3
 R0   0000102e 00000001 00000202 00000030 00000012 7fa22670 00000000 00000001
            t0       t1       t2       t3       t4       t5       t6       t7
 R8   7fa22570 7fa22670 2bbe548c 00000001 00100000 e2f038ed 808c1c90 808c1ca8
            s0       s1       s2       s3       s4       s5       s6       s7
 R16  7fa22670 ffffffff 2bbe0aa4 00000012 00000001 7fa22824 00000000 00000000
            t8       t9       k0       k1       gp       sp       s8       ra
 R24  00000000 2bb55920 00000000 00000000 2bbe75d0 7fa212a0 00417e5c 004b3988
        status       lo       hi badvaddr    cause       pc
      0100ff13 00003ffc 00000000 004b37ec 50800020 2bb5595c
          fcsr      fir      hi1      lo1      hi2      lo2      hi3      lo3
      00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
        dspctl  restart
      00000000 0000102e
(gdb)
```

Cool! We have a debugger.

# Conclusion
Secure infrastructure is important. It is important even to a digital nomad, whether they are a permanent nomad or just a temporary one. Based on research by security professionals, we've seen how hard it can be to get secure infrastructure on the go. HooToo tries to provide an additional layer of security via the Trip Mate travel router.

In this post, we have discovered the surface area that could potentially be used for attacks. We have also seen how a researcher could gain shell access to their device by uploading fake firmware updates. Using these methods, it becomes possible to obtain the binaries that execute on the device as well as set up a dynamic analysis environment.
















