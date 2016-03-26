---
layout: post
title: Automating the UI for blackbox testing
draft: false
---

During blackbox security testing, it is often the case that you need to explore the application. Mostly to understand what it does and what sort of interactions it has with the outside world. It is also a good way to determine what code a user might end up exercising during their use of the application. In case of iOS, most of the App activity will be user triggered and the other parts will be things like polling of the web api for changes. Either way, the App's activity and any potential vulnerabilities are largely triggered by the user.

In this post I introduce __CHAOTICMARCH__ (CM), an engine for driving the UI while doing blackbox testing of an iOS App. CM is a scriptable engine that comes with some basic scripts to locate and trigger buttons. It gives the researcher the freedom to define their own logic for however they wish to perform the test.

I would like to encourage researchers to develop and submit their own logic, so that the community could have a knowledge base for general and specific testing of iOS Apps. Together, we could truly build up an amazing set of automated tests that would be transferable between versions or even applications. A large base would enable us to track changes and keep tests as thorough as possible.

The source code and the user manual is located at the [CHAOTICMARCH](https://github.com/nologic/chaoticmarch) GitHub repository. The code is, of course, still in very early stages, but it is very stable and will be extended in the near future. Also we can utilize [objc_trace](https://github.com/nologic/objc_trace) (or similar) tool to gather code coverage information. _objc_trace_ records the Objective-C functions that have been executed, similar to the functionality of _ltrace_.

## iOS UI Constructs

At the low levels, the UI on iOS is actually quite simple. Basically all of the components stem from the `UIView` base class and are organized as a tree rooted at `UIApp.keyWindow`. To access the children you would use the `subviews` array available at each component:

```javascript
cy# UIApp.keyWindow.subviews
@[#"<UIView: 0x14552a690; frame = (0 0; 320 568); autoresize = W+H; 
  layer = <CALayer: 0x174037d80>>",
  #"<UIView: 0x145699a50; frame = (39.5 327.5; 40 40); 
  clipsToBounds = YES; alpha = 0; layer = <CALayer: 0x17022eb20>>"]
```

This is the abstract representation which is then used to draw components on the screen. You can also list the entire UI tree for examination by using [Cycript](http://www.cycript.org/). Cycript is a scriptable inspection tool that lets users analyzer the internal state of the App. It can be installed using the Cydia appstore. This appstore is installed by any of the popular Chinese jailbreaks. [Pangu](http://pangu.io/) or [Taig](http://www.taig.com/en/) are the current front runners. The UI tree we will be dealing with looks like this:

```javascript
cy# UIApp.keyWindow .recursiveDescription
@"<UIWindow: 0x1456209f0; frame = (0 0; 320 568); gestureRecognizers = <NSArray: 0x170053560>; layer = <UIWindowLayer: 0x170033de0>>
   | <UIView: 0x14552a690; frame = (0 0; 320 568); autoresize = W+H; layer = <CALayer: 0x174037d80>>
   |    | <_UILayoutGuide: 0x14553cdf0; frame = (0 0; 0 20); hidden = YES; layer = <CALayer: 0x17403fac0>>
   |    | <_UILayoutGuide: 0x14553d280; frame = (0 568; 0 0); hidden = YES; layer = <CALayer: 0x17422ac60>>
   |    | <UITableView: 0x145858e00; frame = (0 0; 320 568); clipsToBounds = YES; opaque = NO; autoresize = W+H; gestureRecognizers = <NSArray: 0x170241500>; layer = <CALayer: 0x17003df20>; contentOffset: {0, 0}; contentSize: {320, 867.5}>
   |    |    | <UITableViewWrapperView: 0x145638c30; frame = (0 0; 320 568); gestureRecognizers = <NSArray: 0x1702418c0>; layer = <CALayer: 0x17003fbe0>; contentOffset: {0, 0}; contentSize: {320, 568}>
   |    |    |    | <UITableViewCell: 0x145634f00; frame = (0 553.5; 320 44); text = 'Transport Layer Security'; autoresize = W; layer = <CALayer: 0x17003d6c0>>
   |    |    |    |    | <UITableViewCellContentView: 0x145635250; frame = (0 0; 286 44); opaque = NO; gestureRecognizers = <NSArray: 0x174249e10>; layer = <CALayer: 0x17003d660>>
   |    |    |    |    |    | <UITableViewLabel: 0x145635370; frame = (16 0; 269 44); text = 'Transport Layer Security'; clipsToBounds = YES; opaque = NO; layer = <_UILabelLayer: 0x170099e60>>
```

Of course, the tree above is cut off - but you get the idea. This example comes from the DamnVulnerableApp UI. The full tree goes on for several pages and has a similar repeating pattern. At this point I would like to thank Objective-C for providing us with so much metadata in the binary. We will be using this to develop our automation mechanisms.

## Scripting a click around
Without going into too many details, we want to click on buttons, fill in forms and swipe scrollable things. However, this means that we need to be able to accurately detect buttons, forms and swipable areas. Swiping is harder but buttons and forms are actually relatively easy. We simply have to choose components that qualify as such items. For example, buttons are selected as follows:

```lua
-- Basically anything we might consider clickable
local buttons = findOfTypes("UIButton", "UINavigationItemButtonView", 
    "UINavigationItemView", "_UIAlertControllerActionView", 
    "UISegmentLabel", "UILabel", "")
```

This code is found as part of the `getButton` function in `post_all-common.lua`. Please read the repository README for details about how the LUA scripts are structured and loaded. This code is loaded for all apps as a library that you could use. The function will return a LUA map of a button description. A button map looks like this:

```javascript
{
	"x": [x - coordinate, top-left corner],
	"y": [y - coordinate],
	"width": [number],
	"height": [number],
	"text": [best guess at text of the button]
}
```

The `findOfTypes` function returns a LUA array i.e. number keyed map, of the button description maps. The `getButton` function will look for the button that hasn't been clicked yet. This click state is passed to the `getButton` function. The state is a map that should be maintained by the user. Once a button has been clicked, the user should enter a key of the button text into the state map.

We use this while loop in `post_all-click_around.lua` script to exercise the various buttons on the screen. The process is really quite simple. Here's a reduced size code that accomplishes just what we want.

```lua
while (attempts > 0) do
	local button = getButton(clickedButtons)

	if(button ~= nil) then
		click_button(button)

		if(button["text"] ~= nil) then
			clickedButtons[button["text"]] = 1
		end
	else
		-- check to make sure we are not in alert
		check_alert()

		if(waitTime == 0) then
			-- do a reset and maybe try again
		else
			-- wait less
			waitTime = waitTime - 1
		end
	end
end
```

On the high level, it iterates across various clickable things and enters them into the state to prevent repetition. After a button is clicked, the loop will wait some time to let the App react. Then it will look for another button. The process is very predictable and reproducible. With this mechanism it would be possible to build more complex logic, although at the moment we don't have a way of reading the meaning of an image button.

The `click_button` function is actually built on top of `touchDown` and `touchUp` mechanisms. The touch functions use the [SimulateTouch](https://github.com/iolate/SimulateTouch) library to generate touch events which in tern simulates button click events. The function will also draw a circle on the screen to indicate where CHAOTICMARCH has clicked. This is just a convenience measure to show where the script has clicked.

```lua
function click_button(button)
    local x = button["x"] + math.floor((button["width"]/2))
    local y = button["y"] + math.floor((button["height"]/2))

    showCircle(0, x, y, 20);

    touchDown(0, x, y)
    usleep(100000)
    touchUp(0, x, y)

    hideCircle(0);
end
```

Now, because we are polling the screen for buttons every iteration we might end up in a situation where there are no buttons. However, it may be because the user is seeing an alert box. Such boxes are still within the App UI tree but do not really contain buttons. So, the `check_alert` function will look for labels that match expected text such as "Ok". It will click that text in the hopes of getting rid of the alert box. This doesn't always work and can definitely be made more accurate. However, it covers many use cases.

Once there are no buttons left, we wait for a minute or so. This is done using the `waitTime` variable in the main loop. It is a count down variable, which along with the sleep at every loop iteration creates a wait interval. This is where the researcher gets a chance to assist the engine and go somewhere new or for the App to react and change it's interface.

## Demonstration
What's a tool without a video demo? So, let's have a look at how it performs with a simple application. This particular App is mostly just a wrapper around a webview. The webview will perform most of the heavy lifting, but there are still some UI components for us to interact with.

<center>
<iframe width="420" height="315" src="https://www.youtube.com/embed/Gtd9wOpFK8M" frameborder="0" allowfullscreen></iframe></center>

A demo speaks a thousand words. The culmination of everything we've talked about above is shown in this video. We take an App by [HD Supplies](https://itunes.apple.com/us/app/hd-supply-facilities-maintenance/id585691352) and let CHAOTICMARCH have its way with the App. As you can see it detects many buttons and enters the text into the search box. Also, in this demo, I show the capability of replaying preprogrammed touch events. These events can be recorded using something like [AutoTouch](https://autotouch.net). If you use this tool to record touch events, then the output script will be directly compatible with CHAOTICMARCH.

Of course, it would be nice if the scripts are smarter in recognizing the semantics of the clickable and text field components. This is something we are still working on. Using LUA for this purpose makes things much simpler as we can focus on the logic rather than the mechanics.

## Conclusion
We have introduced CHAOTICMARCH, a tool for automating blackbox testing of iOS Apps. The tool injects into a running application to query the UI and trigger events. The logic is driven by an automatically loaded LUA script. Once the UI is queried, the LUA script will decide which buttons to click and forms to fill in. 

Using CHAOTICMATCH frees the researchers from having to manually explore the application. Also, it lets us, as a community, to build up a knowledge base of scripts to handle edge cases and come up with innovative algorithms to perform testing. In combination with other tools such as [MITM Proxy](https://mitmproxy.org/) and [Objc_trace](https://github.com/nologic/objc_trace) we can develop a decent coverage map of the App's activity.

