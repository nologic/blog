---
layout: post
title: Some folks lost their touch
draft: true
---

In an earlier post, I introduced CHAOTICMARCH - simple tool for simulating a user's interaction with an app. It worked well and has helped me a lot with testing. However, all was not well. Every now and then, too often for my comform, the tool's requests for touch were getting ignored. For example, CHAOTICMARCH would find a button and try to click it. You'd see the logged events and the little circle show up on the screen where the event should have occured, but the app would ignore it as if nothing happened. This was very frustrating to me and I was determined to find the root cause. That took me down a pretty deep rabbit hole. To find my way out, I built LLDB scripts, learned about iOS IPC and read lots of code. With this post, I would like to share my insights and lessons.

## TL;DR;

iPhones are relatively small devices and, to provide a smooth user experience, Apple has to be really careful with task scheduling. Prioritized task queues are used for this. The queueing system is nicely explained in the [Run, RunLoop, Run](http://bou.io/RunRunLoopRun.html) blog post. I had this missing touch problem to solve, I've done a lot of debugging only to realize that the events were being ignored because the device was busy animating the fading circles. I use those circles to show where the clicks have occured. However, in the process I built a sniffer for mach ports and found a mild bug in the simulate touch library that could be used to crash `backboardd` which will cause `SpringBoard` to restart.

-----

