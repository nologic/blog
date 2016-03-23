---
layout: post
title: Automating the UI for blackbox testing
draft: true
---

During blackbox security testing, it is often the case that you need to explore the application. Mostly, to understand what it does and what sort of interactions it has with the outside world. It is also a good way to determine what code a user might end up exercising during their use of the application. In case of iOS, most of the App activity will be user triggered and the other parts will be things like polling for changes. Either way, the App's activity and any potential vulnerabilities are largely triggered by the user.

In this post I introduce __CHAOTICMARCH__ (CM), an engine for driving the UI for doing blackbox testing of an iOS App. CM is a scriptable engine that comes with some basic scripts to locate and trigger buttons. It gives the user the freedom to define their own logic for however they wish to perform the test.

I would like to encourage researchers to develop and submit their own logic, so that the community could have a knowledge base for general and specific testing of iOS Apps. Together, we could truly build up an amazing set of automated tests that would be transferable between versions or even applications. A large dataset would able us to track changes and keep tests as thorough as possible.

The source code and a user manual is located in the the [CHAOTICMARCH](https://github.com/nologic/chaoticmarch) GitHub repository. The code is, of course, still in very early stages, but it is very stable and will be extended more in the near future. We will also utilize [objc_trace](https://github.com/nologic/objc_trace) tool to gather code coverage information.

# iOS UI Constructs

The UI on iOS is actually quite simple. Basically all of the components step from the `UIView` class and are organized as a tree rooted at `UIApp.keyWindow`. To access children you would use the `subviews` array available at each component:

```javascript
cy# UIApp.keyWindow.subviews
@[#"<UIView: 0x14552a690; frame = (0 0; 320 568); autoresize = W+H; layer = <CALayer: 0x174037d80>>",#"<UIView: 0x145699a50; frame = (39.5 327.5; 40 40); clipsToBounds = YES; alpha = 0; layer = <CALayer: 0x17022eb20>>"]
```

You can also list the entire UI tree for examination when you use [Cycrypt](http://www.cycript.org/). Cycrypt is a scriptable inspection tool that let's user analyzer the internal state of the App. It can be installed using the Cydia appstore. The UI tree we will be dealing with looks like this:

```javascript
cy# ?expand
expand == true
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

Of course, the tree above is cut off - but you get the idea. This example comes from the DamnVulnerableApp UI. The full tree goes on for several pages and has a similar repeating pattern. At this point I would like to thank Objective-C for providing so much metadata. We will be using this to develop out automation mechanisms.

# Scripting a click around
Without going into too much details, we want to click on buttons, fill in forms and swipe scrollable things. However, this means that we need to be able to accurately detect buttons, form and swipable areas. Swiping is harder but buttons and forms are actually relatively easy. We simply have to choose components that qualify as such items. For example, buttons are selected as follows:

```lua
-- Basically anything we might consider clickable
local buttons = findOfTypes("UIButton", "UINavigationItemButtonView", 
    "UINavigationItemView", "_UIAlertControllerActionView", "UISegmentLabel", 
    "UILabel", "")
```

This code is found as part of the `getButton` function in `post_all-common.lua`. This code is loaded for all app as a library that you could use. The function will return a LUA map of a button description. A button looks like this:

```javascript
{
	"x": [x - coordinate, top-left corner],
	"y": [y - coordinate],
	"width": [number],
	"height": [number],
	"text": [best guess at text of the button]
}
```

The `findOfTypes` function returns a LUA array i.e. number keyed map, of the button description maps. The the `getButton` function will look for the button that hasn't been clicked yet. This state is passed to the `getButton` function. The state is a map that should be maintained by the user. Once a button has been clicked, the user should enter a key of the button text into the state map.

We use this function is `post_all-click_around.lua` script to exercise the various buttons on the screen. The process is really quite simple. Here's a reduced sized code that accomplishes just what we want.

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

Basically, it iterates across various clickable things and enters them into the state to prevent repetition. After a button is clicked, the loop will wait some time to let the App react and then will look for another button. The process is very predictable and reproducible. With this mechanism it would be possible to build more complex logic.

The `click_button` function is actually built on top of `touchDown` and `touchUp` mechanisms. It will also draw a circle on the screen to indicate where CHAOTICMARCH has clicked.

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
