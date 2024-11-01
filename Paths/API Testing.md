# API Recon

- Identify API endpoints
- Once you have identified the endpoints, you need to determine how to interact with them:
- You should find out information about the following:
	- The input data the API processes, including both compulsory and optional parameters.
	- The types of requests the API accepts, including supported HTTP methods and media formats.
	- Rate limits and authentication mechanisms.
	
# API Documentation

- Documentation can be in both human-readable and machine-readable forms.
- Human-readable documentation is designed for developers to understand how to use the API.
- Machine-readable documentation is designed to be processed by software for automating tasks like API integration and validation. It's written in structured formats like JSON or XML.
- API documentation is often publicly available, particularly if the API is intended for use by external developers.
- If API documentation isn't openly available, you may still be able to access it by browsing applications that use the API.
- Look for endpoints that may refer to API documentation, for example:
	- `/api`
	- `/swagger/index.html`
	- `/openapi.json`
- If you identify an endpoint for a resource, make sure to investigate the base path. For example, if you identify the resource endpoint `/api/swagger/v1/users/123`, then you should investigate the following paths:
	- `/api/swagger/v1`
	- `/api/swagger`
	- `/api`
- You can use Burp Scanner to crawl and audit OpenAPI documentation, or any other documentation in JSON or YAML format. You can also parse OpenAPI documentation using the OpenAPI Parser BApp.
- You may also be able to use a specialized tool to test the documented endpoints, such as Postman or SoapUI.

# Identifying API endpoints

- You can also gather a lot of information by browsing applications that use the API.
- You can use Burp Scanner to crawl the application, then manually investigate interesting attack surface using Burp's browser.
- While browsing the application, look for patterns that suggest API endpoints in the URL structure, such as `/api/`.
- Also lookout for `Javascript` files. These can contain references to API endpoints that you haven't triggered directly via the web browser.
- Burp Scanner automatically extracts some endpoints during crawls, but for a more heavyweight extraction, use the JS Link Finder BApp. You can also manually review JavaScript files in Burp.

# Interacting with API endpoints

- You could investigate how the API responds to changing the HTTP method and media type.
- Review error messages and other responses closely.

# Identifying supported HTTP methods

- The HTTP method specifies the action to be performed on a resource.
- An API endpoint may support different HTTP methods. It's therefore important to test all potential methods when you're investigating API endpoints.
- You can use the built-in **HTTP verbs** list in Burp Intruder to automatically cycle through a range of methods.
- When testing different HTTP methods, target low-priority objects.

# Identifying supported content types

- API endpoints often expect data in a specific format. They may therefore behave differently depending on the content type of the data provided in a request. Changing the content type may enable you to:
	- Trigger errors that disclose useful information.
	- Bypass flawed defenses.
	- Take advantage of differences in processing logic. For example, an API may be secure when handling JSON data but susceptible to injection attacks when dealing with XML.
- To change the content type, modify the `Content-Type` header, then reformat the request body accordingly.
- You can use the Content type converter BApp to automatically convert data submitted within requests between XML and JSON.
---
# Finding hidden parameters

- Burp Intruder enables you to automatically discover hidden parameters, using a wordlist of common parameter names to replace existing parameters or add new parameters. Make sure you also include names that are relevant to the application, based on your initial recon.
- The Param miner BApp enables you to automatically guess up to 65,536 param names per request. Param miner automatically guesses names that are relevant to the application, based on information taken from the scope.
- The Content discovery tool enables you to discover content that isn't linked from visible content that you can browse to, including parameters.

# Mass assignment vulnerabilities

- Mass assignment (also known as auto-binding) can inadvertently create hidden parameters. 
- It occurs when software frameworks automatically bind request parameters to fields on an internal object. 
- Mass assignment may therefore result in the application supporting parameters that were never intended to be processed by the developer.
# Identifying hidden parameters

- Since mass assignment creates parameters from object fields, you can often identify these hidden parameters by manually examining objects returned by the API.
- For example, consider a `PATCH /api/users/` request, which enables users to update their username and email, and includes the following JSON:
 
```json
{
	"username": "wiener",
	"email": "wiener@example.com",
}
```

- A concurrent `GET /api/users/123` request returns the following JSON:

```json
{
	"id": 123,
	"name": "John Doe",
	"email": "john@example.com",
	"isAdmin": "false",
} 
```

- This may indicate that the hidden `id` and `isAdmin` parameters are bound to the internal user object, alongside the updated username and email parameters

# Testing mass assignment vulnerabilities
- To test whether you can modify the enumerated `isAdmin` parameter value, add it to the `PATCH` request:

```json
{
	"username": "wiener",
	"email": "wiener@example.com",
	"isAdmin": false,
}
```

- In addition, send a `PATCH` request with an invalid `isAdmin` parameter value:

```json
{
	"username": "wiener",
	"email": "wiener@example.com",
	"isAdmin": "foo",
}
```

- If the application behaves differently, this may suggest that the invalid value impacts the query logic, but the valid value doesn't. This may indicate that the parameter can be successfully updated by the user.
- You can then send a `PATCH` request with the `isAdmin` parameter value set to `true`, to try and exploit the vulnerability:

```json
{
	"username": "wiener",
	"email": "wiener@example.com",
	"isAdmin": true,
}
```

- If the `isAdmin` value in the request is bound to the user object without adequate validation and sanitization, the user `wiener` may be incorrectly granted admin privileges. 
---
# Preventing vulnerabilities in APIs

- When designing APIs, make sure that security is a consideration from the beginning. In particular, make sure that you:

- Secure your documentation if you don't intend your API to be publicly accessible.
- Ensure your documentation is kept up to date so that legitimate testers have full visibility of the API's attack surface.
- Apply an allowlist of permitted HTTP methods.
- Validate that the content type is expected for each request or response.
- Use generic error messages to avoid giving away information that may be useful for an attacker.
- Use protective measures on all versions of your API, not just the current production version.
- To prevent mass assignment vulnerabilities, allowlist the properties that can be updated by the user, and blocklist sensitive properties that shouldn't be updated by the user.
---
# Server-side parameter pollution

- Server-side parameter pollution occurs when a website embeds user input in a server-side request to an internal API without adequate encoding. 
- This means that an attacker may be able to manipulate or inject parameters
- Which may enable them to:
	- **Override existing parameters.**
	- **Modify the application behavior.**
	- **Access unauthorized data.**
- You can test any user input for any kind of parameter pollution. 
	- **Query parameters**
	- **Form fields**
	- **Headers**
	- **URL Path parameters**
# Testing for server-side parameter pollution in the query string

- Place query syntax characters like **`#`**, **`&`**, and **`=`** in your input and observe how the application responds.
- Consider a vulnerable application that enables you to search for other users based on their username. When you search for a user, your browser makes the following request:

```http
GET /userSearch?name=peter&back=/home
```

- To retrieve user information, the server queries an internal API with the following request:

```http
GET /users/search?name=peter&publicProfile=true
```

# Truncating query strings

- You can use a URL-encoded **`#`** character to attempt to truncate the server-side request.
- To help you interpret the response, you could also add a string after the # character.
- It's essential that you URL-encode the # character. Otherwise the front-end application will interpret it as a fragment identifier and it won't be passed to the internal API.

- For example, you could modify the query string to the following:

```html
GET /userSearch?name=peter%23foo&back=/home
```
- The front-end will try to access the following URL:

```html
GET /users/search?name=peter#foo&publicProfile=true
```

# Injecting invalid parameters

- You can use an URL-encoded & character to attempt to add a second parameter to the server-side request.

- For example, you could modify the query string to the following:

```html
GET /userSearch?name=peter%26foo=xyz&back=/home
```

- This results in the following server-side request to the internal API:

```html
GET /users/search?name=peter&foo=xyz&publicProfile=true
```

# Injecting valid parameters

- If you're able to modify the query string, you can then attempt to add a second valid parameter to the server-side request.

- For example, if you've identified the email parameter, you could add it to the query string as follows:

```html
GET /userSearch?name=peter%26email=foo&back=/home

```

- This results in the following server-side request to the internal API:

```html
GET /users/search?name=peter&email=foo&publicProfile=true
```

# Overriding existing parameters

- To confirm whether the application is vulnerable to server-side parameter pollution, you could try to override the original parameter. Do this by injecting a second parameter with the same name.

- For example, you could modify the query string to the following:

```html
GET /userSearch?name=peter%26name=carlos&back=/home
```

- This results in the following server-side request to the internal API:

```html
GET /users/search?name=peter&name=carlos&publicProfile=true
```

- The internal API interprets two name parameters.
- The impact of this depends on how the application processes the second parameter.
- This varies across different web technologies. For example:

	- PHP parses the last parameter only. This would result in a user search for carlos.
	- ASP.NET combines both parameters. This would result in a user search for peter,carlos, which might result in an Invalid username error message.
	- Node.js / express parses the first parameter only. This would result in a user search for peter, giving an unchanged result.

- If you're able to override the original parameter, you may be able to conduct an exploit. For example, you could add name=administrator to the request. This may enable you to log in as the administrator user.
# Testing for server-side parameter pollution in REST paths

- A RESTful API may place parameter names and values in the URL path, rather than the query string.
- An attacker may be able to manipulate server-side URL path parameters to exploit the API.
- To test for this vulnerability, add path traversal sequences to modify parameters and observe how the application responds.
- You could submit URL-encoded peter/../admin as the value of the name parameter:

```html
GET /edit_profile.php?name=peter%2f..%2fadmin
```

- This may result in the following server-side request:

```html
GET /api/private/users/peter/../admin
```

- If the server-side client or back-end API normalize this path, it may be resolved to /api/private/users/admin.
# Testing for server-side parameter pollution in structured data formats

- An attacker may be able to manipulate parameters to exploit vulnerabilities in the server's processing of other structured data formats, such as a JSON or XML.
- To test for this, inject unexpected structured data into user inputs and see how the server responds.
- Consider an application that enables users to edit their profile, then applies their changes with a request to a server-side API. When you edit your name, your browser makes the following request:

```html
POST /myaccount
name=peter
```

- This results in the following server-side request:

```html
PATCH /users/7312/update
{"name":"peter"}
```

- You can attempt to add the `access_level` parameter to the request as follows:

```html
POST /myaccount
name=peter","access_level":"administrator
```

- If the user input is added to the server-side JSON data without adequate validation or sanitization, this results in the following server-side request:

```html
PATCH /users/7312/update
{name="peter","access_level":"administrator"}

```
- **This may result in the user peter being given administrator access.**

- Consider a similar example, but where the client-side user input is in JSON data. When you edit your name, your browser makes the following request:

```html
POST /myaccount
{"name": "peter"}
```

- This results in the following server-side request:

```html
PATCH /users/7312/update
{"name":"peter"}
```

- You can attempt to add the `access_level` parameter to the request as follows:

```html
POST /myaccount
{"name": "peter\",\"access_level\":\"administrator"}
```

- If the user input is decoded, then added to the server-side JSON data without adequate encoding, this results in the following server-side request:

```html
PATCH /users/7312/update
{"name":"peter","access_level":"administrator"}
```

- **Again, this may result in the user peter being given administrator access.**

- Structured format injection can also occur in responses. For example, this can occur if user input is stored securely in a database, then embedded into a JSON response from a back-end API without adequate encoding. You can usually detect and exploit structured format injection in responses in the same way you can in requests.
---
# Testing with automated tools

- You can also use the Backslash Powered Scanner BApp to identify server-side injection vulnerabilities.
---
# Preventing server-side parameter pollution

- Use an allowlist to define characters that don't need encoding
- Make sure all other user input is encoded before it's included in a server-side request.
- You should also make sure that all input adheres to the expected format and structure.