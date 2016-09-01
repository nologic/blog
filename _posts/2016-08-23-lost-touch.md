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
The problem we are trying solve is the mystery of why touch events have been disappearing. My first intuition was that perhaps these port messages were not getting to the server for some reason. So, I've decided to sniff them in the same way that I would with network traffic. After much googling, I found almost nothing for sniffing mach messages except for an old blog about [mach_shark](http://blog.wuntee.sexy/CVE-2015-3795) which unfortunately was not released (and, on the last check the blog site was down - here's a [web archive link](http://web.archive.org/web/20160413172707/http://blog.wuntee.sexy/CVE-2015-3795/)).
-----

