# What is authentication?

- Authentication is the process of verifying the identity of a user or client.

- There are three main types of authentication:

	- Something you know, such as a password or the answer to a security question. These are sometimes called `knowledge factors`.
	- Something you have, This is a physical object such as a mobile phone or security token. These are sometimes called `possession factors`.
	- Something you are or do. For example, your biometrics or patterns of behavior. These are sometimes called `inherence factors`.

# What is the difference between authentication and authorization?

- `Authentication` is the process of verifying that a user is who they claim to be. 

- `Authorization` involves verifying whether a user is allowed to do something.

# Vulnerabilities in password-based login

- For websites that adopt a password-based login process, users either register for an account themselves or they are assigned an account by an administrator.

- This account is associated with a unique username and a secret password, which the user enters in a login form to authenticate themselves.

- In this scenario, the fact that they know the secret password is taken as sufficient proof of the user's identity. 

## Brute-force attacks

- A brute-force attack is when an attacker uses a system of trial and error to guess valid user credentials. These attacks are typically automated using wordlists of usernames and passwords. 

- By also using basic logic or publicly available knowledge, attackers can fine-tune brute-force attacks to make much more educated guesses. This considerably increases the efficiency of such attacks.

### Brute-force Usernames

- Usernames are especially easy to guess if they conform to a recognizable pattern, such as an email address. For example:`firstname.lastname@somecompany.com`. 

- Sometimes even high-privileged accounts are created using predictable usernames, such as admin or administrator.

- During auditing, check whether the website discloses potential usernames publicly. 

- The name used in the profile is sometimes the same as the login username.

- You should also check HTTP responses to see if any email addresses are disclosed. Occasionally, responses contain email addresses of high-privileged users, such as administrators or IT support.

### Brute-forcing passwords

- Passwords can similarly be brute-forced, with the difficulty varying based on the strength of the password.

- Many websites adopt some form of password policy, which forces users to create high-entropy passwords. This typically involves enforcing passwords with:

	- A minimum number of characters
	- A mixture of lower and uppercase letters
	- At least one special character

- Users often take a password that they can remember and try to crowbar it into fitting the password policy. For example, if `mypassword` is not allowed, users may try something like `Mypassword1!` or `Myp4$$w0rd` instead.

- In cases where the policy requires users to change their passwords on a regular basis, it is also common for users to just make minor, predictable changes to their preferred password. For example, `Mypassword1!` becomes `Mypassword1?` or `Mypassword2!`.

### Username enumeration

- Username enumeration is when an attacker is able to observe changes in the website's behavior in order to identify whether a given username is valid.

- Username enumeration typically occurs either on the login page, for example, when you enter a valid username but an incorrect password, or on registration forms when you enter a username that is already taken. This greatly reduces the time and effort required to brute-force a login because the attacker is able to quickly generate a shortlist of valid usernames.

- While attempting to brute-force a login page, you should pay particular attention to any differences in:

	- **Status codes**: During a brute-force attack, the returned HTTP status code is likely to be the same for the vast majority of guesses because most of them will be wrong. If a guess returns a different status code, this is a strong indication that the username was correct. It is best practice for websites to always return the same status code regardless of the outcome, but this practice is not always followed.

	- **Error messages**: Sometimes the returned error message is different depending on whether both the username AND password are incorrect or only the password was incorrect. It is best practice for websites to use identical, generic messages in both cases, but small typing errors sometimes creep in. Just one character out of place makes the two messages distinct, even in cases where the character is not visible on the rendered page.

	- **Response times**: If most of the requests were handled with a similar response time, any that deviate from this suggest that something different was happening behind the scenes. This is another indication that the guessed username might be correct. For example, a website might only check whether the password is correct if the username is valid. This extra step might cause a slight increase in the response time. This may be subtle, but an attacker can make this delay more obvious by entering an excessively long password that the website takes noticeably longer to handle.

### Flawed brute-force protection

- It is highly likely that a brute-force attack will involve many failed guesses before the attacker successfully compromises an account.

- The two most common ways of preventing brute-force attacks are:

	- Locking the account that the remote user is trying to access if they make too many failed login attempts

	- Blocking the remote user's IP address if they make too many login attempts in quick succession

- Both approaches offer varying degrees of protection, but neither is invulnerable, especially if implemented using flawed logic.

- In some implementations, the counter for the number of failed attempts resets if the IP owner logs in successfully. This means an attacker would simply have to log in to their own account every few attempts to prevent this limit from ever being reached.
- In this case, merely including your own login credentials at regular intervals throughout the wordlist is enough to render this defense virtually useless.

### Account locking

- One way in which websites try to prevent brute-forcing is to lock the account if certain suspicious criteria are met, usually a set number of failed login attempts.
- Just as with normal login errors, responses from the server indicating that an account is locked can also help an attacker to enumerate usernames.

- Locking an account offers a certain amount of protection against targeted brute-forcing of a specific account.
- However, this approach fails to adequately prevent brute-force attacks in which the attacker is just trying to gain access to any random account they can.

- For example, the following method can be used to work around this kind of protection:

	1. Establish a list of candidate usernames that are likely to be valid. This could be through username enumeration or simply based on a list of common usernames.

	2. Decide on a very small shortlist of passwords that you think at least one user is likely to have. Crucially, the number of passwords you select must not exceed the number of login attempts allowed.
	
	3. Using a tool such as Burp Intruder, try each of the selected passwords with each of the candidate usernames. This way, you can attempt to brute-force every account without triggering the account lock.
	
	- You only need a single user to use one of the three passwords in order to compromise an account.

### Credential Stuffing

- Account locking also fails to protect against `credential stuffing` attacks.

- This involves using a massive dictionary of `username:password` pairs, composed of genuine login credentials stolen in data breaches.

- `Credential stuffing` relies on the fact that many people reuse the same username and password on multiple websites.

- Account locking does not protect against credential stuffing because each username is only being attempted once.

- Credential stuffing is particularly dangerous because it can sometimes result in the attacker compromising many different accounts with just a single automated attack.

### User rate limiting

- Another way websites try to prevent brute-force attacks is through user rate limiting. 

- Making too many login requests within a short period of time causes your IP address to be blocked.

- Typically, the IP can only be unblocked in one of the following ways:

	- Automatically after a certain period of time has elapsed
	
	- Manually by an administrator

	- Manually by the user after successfully completing a CAPTCHA

- User rate limiting is sometimes preferred to account locking due to being less prone to username enumeration and denial of service attacks. 

- However, there are several ways an attacker can manipulate their apparent IP in order to bypass the block.

- As the limit is based on the rate of HTTP requests sent from the user's IP address, it is sometimes also possible to bypass this defense if you can work out how to guess multiple passwords with a single request.

## HTTP basic authentication

- In HTTP basic authentication, the client receives an authentication token from the server, which is constructed by concatenating the username and password, and encoding it in `Base64`.

- This token is stored and managed by the browser, which automatically adds it to the Authorization header of every subsequent request as follows:
```
Authorization: Basic base64(username:password)
```

- Unless the website also implements HSTS, user credentials are open to being captured in a man-in-the-middle attack.

- HTTP basic authentication often don't support brute-force protection. As the token consists exclusively of static values, this can leave it vulnerable to being brute-forced.

- HTTP basic authentication is also particularly vulnerable to session-related exploits, notably CSRF, against which it offers no protection on its own.

- the credentials exposed in this way might be reused in other, more confidential contexts.

# Vulnerabilities in multi-factor authentication

- Verifying biometric factors is impractical for most websites. 

- it is increasingly common to see both mandatory and optional two-factor authentication (2FA)
- This usually requires users to enter both a traditional password and a temporary verification code from an out-of-band physical device in their possession.

- Full benefits of multi-factor authentication are only achieved by verifying multiple different factors.

## Two-factor authentication tokens

- RSA token or keypad devices that you might use to access your online banking or work laptop.
- These dedicated devices have the advantage of generating the verification code directly. such as `Google Authenticator`

- On the other hand, some websites send verification codes to a user's mobile phone as a text message.

- it is open to abuse. Firstly, the code can be intercepted. There is also a risk of SIM swapping. The attacker would then receive all SMS messages sent to the victim, including the one containing their verification code.

## Bypassing two-factor authentication

- If the user is first prompted to enter a password, and then prompted to enter a verification code on a separate page, the user is effectively in a "logged in" state before they have entered the verification code. Occasionally, you will find that a website doesn't actually check whether or not you completed the second step before loading the page.
### Flawed two-factor verification logic

- Sometimes flawed logic in two-factor authentication means that after a user has completed the initial login step, the website doesn't adequately verify that the same user is completing the second step.

#### Example

- the user logs in:
```
POST /login-steps/first HTTP/1.1
Host: vulnerable-website.com

username=carlos&password=qwerty
```

- Servers then, assign a cookie that relates to the account:
```
HTTP/1.1 200 OK
Set-Cookie: account=carlos

GET /login-steps/second HTTP/1.1
Cookie: account=carlos
```

- When submitting the verification code, the request uses this cookie to determine which account the user is trying to access:
```
POST /login-steps/second HTTP/1.1
Host: vulnerable-website.com
Cookie: account=carlos

verification-code=123456
```

- An attacker could log in using their own credentials but then change the value of the account cookie to any arbitrary username when submitting the verification code:
```
POST /login-steps/second HTTP/1.1
Host: vulnerable-website.com
Cookie: account=victim-user

verification-code=123456
```

- This is extremely dangerous if the attacker is then able to brute-force the verification code as it would allow them to log in to arbitrary users' accounts based entirely on their username. They would never even need to know the user's password.

## Brute-forcing 2FA verification codes

- As with passwords, websites need to take steps to prevent brute-forcing of the `2FA` verification code.

- Some websites attempt to prevent this by automatically logging a user out if they enter a certain number of incorrect verification codes.

- This is ineffective in practice because an advanced attacker can even automate this multi-step process by creating macros for `Burp Intruder`.
- The `Turbo Intruder` extension can also be used for this purpose.

# Vulnerabilities in other authentication mechanisms
## Keeping users logged in

- A common feature is the option to stay logged in even after closing a browser session. This is usually a simple checkbox labeled something like "Remember me" or "Keep me logged in".

- This functionality is often implemented by generating a "remember me" token of some kind, which is then stored in a persistent cookie.

- Possessing this cookie effectively allows you to bypass the entire login process, it is best practice for this cookie to be impractical to guess.

- However, some websites generate this cookie based on a predictable concatenation of static values, such as the username and a timestamp. Some even use the password as part of the cookie.

- This approach is particularly dangerous if an attacker is able to create their own account because they can study their own cookie and potentially deduce how it is generated. Once they work out the formula, they can try to brute-force other users' cookies to gain access to their accounts.

- Some websites assume that if the cookie is encrypted in some way it will not be guessable even if it does use static values. 

- While this may be true if done correctly, naively "encrypting" the cookie using a simple two-way encoding like Base64 offers no protection whatsoever. Even using proper encryption with a one-way hash function is not completely bulletproof.

- If the attacker is able to easily identify the hashing algorithm, and no salt is used, they can potentially brute-force the cookie by simply hashing their wordlists. This method can be used to bypass login attempt limits if a similar limit isn't applied to cookie guesses.

- Even if the attacker is not able to create their own account, they may still be able to exploit this vulnerability. Using the usual techniques, such as XSS, an attacker could steal another user's "remember me" cookie and deduce how the cookie is constructed from that. If the website was built using an open-source framework, the key details of the cookie construction may even be publicly documented.

- In some rare cases, it may be possible to obtain a user's actual password in cleartext from a cookie, even if it is hashed.

- Hashed versions of well-known password lists are available online, so if the user's password appears in one of these lists, decrypting the hash can occasionally be as trivial as just pasting the hash into a search engine.

## Resetting user passwords

- The password reset functionality is inherently dangerous and needs to be implemented securely.

- There are a few different ways that this feature is commonly implemented, with varying degrees of vulnerability.

### Sending passwords by email

- Some websites generate a new password and send this to the user via email.

- Sending persistent passwords over insecure channels is to be avoided.

- In this case, the security relies on either the generated password expiring after a very short period, or the user changing their password again immediately. Otherwise, this approach is highly susceptible to man-in-the-middle attacks.

- Email is also generally not considered secure given that inboxes are both persistent and not really designed for secure storage of confidential information. Many users also automatically sync their inbox between multiple devices across insecure channels.

## Resetting passwords using a URL

- A more robust method of resetting passwords is to send a unique URL to users that takes them to a password reset page.

- Less secure implementations of this method use a URL with an easily guessable parameter to identify which account is being reset:
```
http://vulnerable-website.com/reset-password?user=victim-user
```

- In this example, an attacker could change the user parameter to refer to any username they have identified. They would then be taken straight to a page where they can potentially set a new password for this arbitrary user.

- A better implementation of this process is to generate a high-entropy, hard-to-guess token and create the reset URL based on that.

- In the best case scenario, this URL should provide no hints about which user's password is being reset:
```
http://vulnerable-website.com/reset-password?token=a0ba0d1cb3b63d13822572fcff1a241895d893f659164d4cc550b421ebdd48a8
```

- When the user visits this URL, the system should check whether this token exists on the back-end and, if so, which user's password it is supposed to reset. This token should expire after a short period of time and be destroyed immediately after the password has been reset.

- However, some websites fail to also validate the token again when the reset form is submitted.
- In this case, an attacker could simply visit the reset form from their own account, delete the token, and leverage this page to reset an arbitrary user's password.

- If the URL in the reset email is generated dynamically, this may also be vulnerable to password reset poisoning. In this case, an attacker can potentially steal another user's token and use it change their password.

## Changing user passwords

- Password change functionality can be particularly dangerous if it allows an attacker to access it directly without being logged in as the victim user.

- For example, if the username is provided in a hidden field, an attacker might be able to edit this value in the request to target arbitrary users. This can potentially be exploited to enumerate usernames and brute-force passwords.

## Preventing attacks on your own authentication mechanisms

### Take care with user credentials

-  **Never send any login data over unencrypted connections**. Although you may have implemented `HTTPS` for your login requests, make sure that you enforce this by redirecting any attempted `HTTP` requests to `HTTPS` as well.

- You should also audit your website to make sure that no username or email addresses are disclosed either through publicly accessible profiles or reflected in HTTP responses.

### Don't count on users for security

- Enforce secure behaviour wherever possible.

- Implement a simple password checker. A popular example is the JavaScript library `zxcvbn`, which was developed by Dropbox. 

### Prevent username enumeration

- Identical, generic error messages, and make sure they really are identical.

- You should always return the same HTTP status code with each login request

- Make the response times in different scenarios as indistinguishable as possible.

### Implement robust brute-force protection

- Given how simple constructing a brute-force attack can be, it is vital to ensure that you take steps to prevent, or at least disrupt, any attempts to brute-force logins.

- One of the more effective methods is to implement strict, IP-based user rate limiting. 

- Ideally, you should require the user to complete a CAPTCHA test with every login attempt after a certain limit is reached.

### Triple-check your verification logic

- Auditing any verification or validation logic thoroughly to eliminate flaws is absolutely key to robust authentication.

### Don't forget supplementary functionality

- Remember that a password reset or change is just as valid an attack surface as the main login mechanism.

## Implement proper multi-factor authentication

- While multi-factor authentication may not be practical for every website, when done properly it is much more secure than password-based login alone.
 
- 2FA should be implemented using a dedicated device or app that generates the verification code directly.

- Make sure that the logic in your 2FA checks is sound so that it cannot be easily bypassed.