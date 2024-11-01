# Limit overrun race conditions

- They enable you to exceed some kind of limit imposed buy the business log of the applications.

- When an application proceeds a request enters in a temporary sub-state, it starts when the server starts processing the request and ends when the server update the datebase.

- During this sub-state a small race condition window is generated.
### Possible variations of this kind of attack

- Redeeming a gift card multiple times
- Rating a product multiple times
- Withdrawing or transferring cash in excess of your account balance
- Reusing a single CAPTCHA solution
- bypasssing an anti-brute-force rate limit

>[!bug] Limit Overruns
>Are a subtype of so-called "time-of-check to time-of-use"(TOCTOU) flaws

# Detecting and exploiting limit overrun race conditions with Burp Repeater

1. Identity  single-user or rate-limited endpoint that has some kind of security impact or other useful purpose
2. Issue multiple requests to this endpoint in quick succession to see if you can overrun this limit

- The main challenge is timing the requests so that at least two race windows line up, causing a collision

- This window is often just milliseconds and can be even shorter.

