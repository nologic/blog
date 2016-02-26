---
layout: post
title: Building libraries for iOS
---

In this blog we talk about how to build a library in a simple way. This is designed for those who only care about the quickest and easiest way to build a command line program or a dylib for a jailbroken iOS platform. So, it is not an exhaustive manual of all the possibilities but rather a quick reference guide to get you started.

## Background

Once you have jailbroken your pristine iOS 8 or 9 or whatever phone, you probably want to do something useful with it. Specifically add functionality that wouldn't be available on a non-jailbroken phone. The JB community calls these tweaks. However, all tweaks are just a sets of libraries, configurations and programs. We are interested in how to build those. In this blog we will specifically focus on dylibs because they are cool. Just kidding, we will focus on them because they can be injected into all applications on the jailbroken phone.

Time for some background information. If you jailbreak your iOS device with one of the standard jailbreaking tools, by that I mean TaiG or Pangu jailbreaks, then you will get a whole bunch of infrastructure to go along with it. One of the pieces of that infrastructure will be Cydia and CydiaSubstrate (a.k.a substrate or mobile substrate). Both of those are implemented by Jay Freeman (saurik). Cydia is the jailbreaker's appstore. It's great for getting stuff like GDB and other binary development tools.

Substrate is assisted by a kernel patch. It lets the user load dynamic libraries from this directory.
{% highlight bash %}
  /Library/MobileSubstrate/DynamicLibraries/
{% endhighlight %}

Once the app is loaded into memory all the libraries from that directory will loaded as well. It is very similar to the use of DYLD_INSERT_LIBRARIES from the command line. The only difference is that function interposition won't work. In order to interpose, you would need to use Substrate's MSHookFunction subroutine. This is how tweaks will modify Apps' functionality. NOTE: At this point you have forgone all security and no data, except for the data in the Security Enclave, will be safe. You decide how you want to handle this risk.

## Basics
In order to build one of those libraries, you will need an OS X instance with Xcode command line tools installed. You could probably do this on something other than OS X, but that would just be torture. Once you've committed to development on the iPhone, might as well go all the way.
First, you will need to find the appropriate SDK. Xcode has several, one for each of the Apple products:

```bash
   $ ls /Applications/Xcode.app/Contents/Developer/Platforms/
   AppleTVOS.platform/        MacOSX.platform/     WatchSimulator.platform/ iPhoneSimulator.platform/
   AppleTVSimulator.platform/ WatchOS.platform/    iPhoneOS.platform/
```

The easiest way to find those is to execute the xcrun command:
~~~ bash
  $ xcrun --sdk iphoneos --show-sdk-path
  /Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS9.2.sdk
~~~
We might need this for later. For example, for locating platform specific libraries and frameworks. Next we will want to find the appropriate compiler:
~~~ bash
  $ xcrun --sdk iphoneos --find gcc
  /Applications/Xcode.app/Contents/Developer/usr/bin/gcc
  
  $ xcrun --sdk iphoneos --find clang
  /Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang
~~~
You can use xcrun to find all kinds of binary tools for the target platform. What's nice about the xcrun tool is that we can write portable make files, portable within the Mac ecosystem that is. Your compilation step might look something like this:
~~~ bash
$ `xcrun --sdk iphoneos --find clang` -Os  -isysroot `xcrun --sdk iphoneos --show-sdk-path` -F`xcrun --sdk iphoneos --show-sdk-path`/System/Library/Frameworks  -arch armv7 -arch armv7s -arch arm64 -shared -o main.dylib main.c
~~~

Here, we are basically choosing a compiler and the cross compilation platform. Then we are using clang to compile main.c for the iphoneos platform. This will output a FAT MACH-O file containing versions for armv7/7s (32bit ARM - iPhone 5c and the line) and ARM64 (64bit ARM - iPhone 5s and the like). This is great if you want to be able to support all app bitness. Because we added the -shared flag which is synonymous with -dynamic, the compiler will output a dylib.

The final step is to give your dylib some entitlements so that it can do its business unhindered. This is done using the ldid command that can be obtained from source. The entitlements file is an XML plist with the list of entitlement you wish to have on the command line program or the dylib:
~~~ xml
   <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
   <plist version="1.0">
   <dict>
     <key>com.apple.springboard.debugapplications</key>
     <true/>
     <key>get-task-allow</key>
     <true/>
     <key>proc_info-allow</key>
     <true/>
     <key>task_for_pid-allow</key>
     <true/>
     <key>run-unsigned-code</key>
     <true/>
   </dict>
   </plist>
~~~
  
This file is to be supplied using the -S flag on the ldid command. So in the end your Makefile might look something like this:
~~~ bash
   GCC_BIN=`xcrun --sdk iphoneos --find clang`
   GCC=$(GCC_BASE) -arch armv7 -arch armv7s -arch arm64
   SDK=`xcrun --sdk iphoneos --show-sdk-path`
   CFLAGS =
   GCC_BASE = $(GCC_BIN) -Os $(CFLAGS) -isysroot $(SDK) -F$(SDK)/System/Library/Frameworks -F$(SDK)/System/Library/PrivateFrameworks
   all: main
   main: main.c
    $(GCC) -o $@ $^
    ldid -Sent.xml $@
~~~

_Simples!_

## Using Theos

Everyone loves make files right? Well, I don't but there's not a lot you can do without them. You could use XCode with iOSOpenDev to make life easy for yourself, but it doesn't work in newer versions of XCode (I've used it on 6.4, successfully). However, there's a package that makes jailbreak development with Makefiles easier. It's called Theos. It can be a little confusing to set up, but if you persevere it'll be worth the effort. It will enable you to decouple the build of your tweaks from Xcode and therefore you'll be able to use the latest compilers and build for the latest versions of iOS.

First, install Theos by following the steps on the iphonewiki (section: On Mac OS X or Linux)
* `brew install dpkg`
* extract and place mobile substrate
* make sure there is a link (named theos) to or the actual files to theos in your project directory

I've skipped a few steps but the directions on the site are very clear. Then create a make file that defines a whole bunch of variables:
~~~ make
LIBRARY_NAME = libmain
~~~
This will be used by theos to derive other variable names:
~~~ bash
libmain_FILES = main.m
libmain_LIBRARIES = substrate
libmain_FRAMEWORKS = UIKit 
~~~
Theos will need to know which files to compile and which libraries/frameworks you require. Then you need specify how you want your binaries built - architecture, compiler, target platform, etc:
~~~ make
export TARGET = iphone:clang
export ARCHS = arm64 armv7s
export TARGET_IPHONEOS_DEPLOYMENT_VERSION = 3.0
export TARGET_IPHONEOS_DEPLOYMENT_VERSION_armv7s = 6.0
export TARGET_IPHONEOS_DEPLOYMENT_VERSION_arm64 = 7.0
~~~
This says that I want to build for ARM64 using clang and target it for the 7.0 version of the platform. Also, I want a 32bit ARMV7s for iOS 6.0. Those will be built and placed into the same FAT MACH-O. Finally, we need to tell theos what type of project this is:
~~~ make
include theos/makefiles/common.mk
include $(THEOS_MAKE_PATH)/library.mk
~~~
Since we only want the dylib, we tell it that we are making a library. Then theos will go off and build us a dylib. It will place the output into ./obj/libmain.dylib at which point we are free to upload it into the substrate directory for loading. The output will look something like this:
~~~ bash
$ file obj/libmain.dylib
obj/libmain.dylib: Mach-O universal binary with 3 architectures
obj/libmain.dylib (for architecture armv7): Mach-O dynamically linked shared library arm
obj/libmain.dylib (for architecture armv7s): Mach-O dynamically linked shared library arm
obj/libmain.dylib (for architecture arm64): Mach-O 64-bit dynamically linked shared library
~~~
Once the library is loaded by CydiaSubstrate, the system will run the library constructor like normal and you're free to do whatever you want to the unsuspecting app.

_Simples!_
