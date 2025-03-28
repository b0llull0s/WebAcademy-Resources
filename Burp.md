### Short-Cuts

>[!info] Send to repeater
>```
>CTRL + R
>```

>[!info] URL Decode
>```
>CTRL + SHIFT + U
>```
### Sending Requests in Sequence
1. Create a Group tab
2. Duplicate the request
3. Send the request in sequence

>[!tip]
>Separate connection reduce the chance of interference and can be use to look for clues

>[!important]
>To test for `Race Conditions` use parallel connections

### Turbo Intruder

```python
def queueRequests(target, wordlists):

    # as the target supports HTTP/2, use engine=Engine.BURP2 and concurrentConnections=1 for a single-packet attack
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.BURP2
                           )
    
    # assign the list of candidate passwords from your clipboard
    passwords = wordlists.clipboard
    
    # queue a login request using each password from the wordlist
    # the 'gate' argument withholds the final part of each request until engine.openGate() is invoked
    for password in passwords:
        engine.queue(target.req, password, gate='1')
    
    # once every request has been queued
    # invoke engine.openGate() to send all requests in the given gate simultaneously
    engine.openGate('1')


def handleResponse(req, interesting):
    table.add(req)
```


>[!tip] Use the `Content Type Converter` extension
>- Automatically convert the request method and change a URL-encoded `POST` request to `JSON`.

