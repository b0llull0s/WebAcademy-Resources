>[!info] Cross-site scripting
>- Also known as XSS, is a web security vulnerability that allows an attacker to compromise the interactions that users have with a vulnerable application.
>- It allows an attacker to circumvent the same origin policy, which is designed to segregate different websites from each other. 
>- Normally allow an attacker to masquerade as a victim user.
>- If the victim user has privileged access within the application, then the attacker might be able to gain full control over all of the application's functionality and data.
>
>>[!example] How does XSS work?
>>- By manipulating a vulnerable web site so that it returns malicious JavaScript to users.
>>- When the malicious code executes inside a victim's browser, the attacker can fully compromise their interaction with the application.
>
>>[!tip] Proof of concept
>>- Injecting a payload that causes your own browser to execute some arbitrary JavaScript.
>>- It's long been common practice to use the `alert()` function.
>>
>>>[!warning] `alert()` 
>>>- There's a slight hitch if you use `Chrome`. From `version 92` onward (July 20th, 2021), cross-origin `iframes` are prevented from calling `alert()`.
>>>- In this scenario, we recommend the `print()` function.
>
>>[!bug] XSS Attacks
>>
>>>[!danger] Reflected XSS
>>>- Arises when an application receives data in an HTTP request and includes that data within the immediate response in an unsafe way.
>>>
>>>>[!example]
>>>>```
>>>>https://insecure-website.com/status?message=<script>/*+Bad+stuff+here...+*/</script>
>>>>```
>>>>- If the user visits the URL constructed by the attacker, then the attacker's script executes in the user's browser.
>>
>>>[!danger] Stored XSS
>>>- Also known as persistent or second-order `XSS`.
>>>- Arises when an application receives data from an untrusted source and includes that data within its later HTTP responses in an unsafe way.
>>>
>>>>[!example]
>>>>```
>>>><p><script>/* Bad stuff here... */</script></p>
>>>>```
>>>>- When the application doesn't perform any other processing of the data, an attacker can easily send a message that attacks other users.
>>
>>>[!danger] DOM-based XSS
>>>- Arises when an application contains some client-side JavaScript that processes data from an untrusted source in an unsafe way, usually by writing the data back to the `DOM`.
>>>- If the attacker can control the value of the input field, they can easily construct a malicious value that causes their own script to execute:
>>>
>>>>[!example]
>>>>```
>>>><img src=1 onerror='/* Bad stuff here... */'>
>>>>```
>>>>- The input field would be populated from part of the HTTP request, such as a URL query string parameter, allowing the attacker to deliver an attack using a malicious URL, in the same manner as reflected `XSS`.
>
>>[!info] What can XSS be used for?
>>- Impersonate or masquerade as the victim user.
>>- Carry out any action that the user is able to perform.
>>- Read any data that the user is able to access.
>>- Capture the user's login credentials.
>>- Perform virtual defacement of the web site.
>>- Inject trojan functionality into the web site.
>
>>[!tip] Impact
>>- Generally depends on the nature of the application, its functionality and data, and the status of the compromised user.
>>- In a `brochureware` application, where all users are anonymous and all information is public, the impact will often be minimal.
>>- In an application holding sensitive data, such as banking transactions, emails, or healthcare records, the impact will usually be serious.
>>- If the compromised user has elevated privileges within the application, then the impact will generally be critical, allowing the attacker to take full control of the vulnerable application and compromise all users and their data.
>
>>[!bug] Test for XSS
>>- Normally involves submitting some simple unique input (such as a short alphanumeric string) into every entry point in the application.
>>- Identifying every location where the submitted input is returned in HTTP responses.
>>- And testing each location individually to determine whether suitably crafted input can be used to execute arbitrary JavaScript. 
>>- Manually testing for `DOM-based XSS` arising from URL parameters involves a similar process:
>>- Placing some simple unique input in the parameter.
>>- Using the browser's developer tools to search the DOM for this input.
>>- And testing each location to determine whether it is exploitable.
>
>>[!info] Content security policy - CSP
>>- Is a browser mechanism that aims to mitigate the impact of cross-site scripting and some other vulnerabilities.
>
>>[!danger] Dangling markup injection
>>- Is a technique that can be used to capture data cross-domain in situations where a full cross-site scripting exploit is not possible, due to input filters or other defenses.
>>- It can often be exploited to capture sensitive information that is visible to other users, including CSRF tokens that can be used to perform unauthorized actions on behalf of the user.
>
>>[!info] How to prevent XSS attacks
>>- **Filter input on arrival:** At the point where user input is received, filter as strictly as possible based on what is expected or valid input.
>>- **Encode data on output:** At the point where user-controllable data is output in HTTP responses, encode the output to prevent it from being interpreted as active content.
>>- **Use appropriate response headers:** Use the `Content-Type` and `X-Content-Type-Options` headers to ensure that browsers interpret the responses in the way you intend.
>>- **Content Security Policy:** Use `CSP` to reduce the severity of any `XSS` vulnerabilities that still occur.
>
>>[!tip] Bypassing WAF
>>- First you need to fuzz to know if there are any tags that are not blacklisted.
>>- Take a look at the [Cheat-sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet) and copy `bodies`  to fuzz.
>>- If you find any bodies that match, fuzz now for events --> `<body%20§§=1>`

- 