>[!info] 
>- Business logic vulnerabilities are flaws in the design and implementation of an application that allow an attacker to elicit unintended behavior.
>- This potentially enables attackers to manipulate legitimate functionality to achieve a malicious goal.
>- These flaws are generally the result of failing to anticipate unusual application states that may occur and, consequently, failing to handle them safely.
- [PortSwigger Examples](https://portswigger.net/web-security/logic-flaws/examples)
### Excesive Trust

- [ ] Check if the server properly validates user input
- [ ] Check is the price parameter in only validated in the client-side
- [ ] Bypass the client-side validation with a proxy.
### High-Level Logic

- [ ] Check if the server properly validates user input
- [ ] Check is the amount parameter in only validated in the client-side.
- [ ] Are there any limits that are imposed on the data?
- [ ] What happens when you reach those limits?
- [ ] Is any transformation or normalization being performed on your input?
- [ ] Use Negative numbers to decrease the price.
### Inconsistent Security Control

- [ ] Check if the application has special access for employees
- [ ] Test if the security measures are implement properly across the application.

>[!example]
>- Try to use the company email to bypass access control

### Flawed enforcement of business rules

- [ ] Check whether prices or other values are adjusted based on criteria determined by user actions.
- [ ] Spot the algorithms the applications use to make adjustments and at what point they are being apply.

>[!example]
>- Discount coupons from Online Shops may be vulnerable.
>- Try to apply multiple coupons in alternate order.

### Low-Level Logic Flaw

- [ ] Are there any limits that are imposed on the data?
- [ ] What happens when you reach those limits?
- [ ] Is any transformation or normalization being performed on your input?
- [ ] Check is the price loops back after exceeding the maximum value permitted for an integer in the back-end programming language (2,147,483,647).
- [ ] Adjust the attack for the price to be a positive integer.
### Inconsistent handling of exceptional input

>[!bug] Character Limit Pattern
>The `255-character` limit it's a very common pattern in software development:
>- `255` is the maximum value that can be stored in an `8-bit` unsigned integer `(2^8 - 1)`.
>- Many database systems traditionally use `VARCHAR(255)` as a default or common field length for strings.
>- This specific limit is found in many applications, especially when using older database systems.

- [ ] Map the Application.
- [ ] Look for access restrictions based on email domains.
- [ ] Check for email client functionality in the application
- [ ] Test registration with exceptionally long inputs
- [ ] Check if the application truncates inputs (e.g., 255 characters).
- [ ] Verify where truncation occurs by examining account details after registration
- [ ] Look for differences between what's displayed and what's stored
- [ ] Check if email confirmation works differently than account storage
- [ ] Test if you can receive emails at addresses that appear invalid
- [ ] Calculate the exact position of truncation (255 characters in this case)
- [ ] Position a trusted domain so it appears at the end of the truncated email
- [ ] Use a format like: `long-string@trusted-domain.your-domain.com`
- [ ] Ensure the "@trusted-domain" ends exactly at the truncation point
- [ ] Confirm email delivery to your actual address
- [ ] Verify the truncated address in your account after logging in
- [ ] Check for new privileges or access based on the spoofed domain
### Weak isolation on dual-use endpoint

- [ ] Identify all parameters in the request (URL, POST body, cookies).
- [ ] Remove one parameter at a time and observe the server's response.
- [ ] Remove the value of the parameter.
- [ ] Remove the entire parameter.
- [ ] Compare the response to the normal behavior to identify anomalies.
- [ ] Repeat for all parameters in the request.
- [ ] Follow multi-stage workflows (e.g., login, checkout, account creation).
- [ ] Tamper with parameters in one step and observe the effect on subsequent steps.
- [ ] Check if the application behaves unexpectedly or bypasses validation.
- [ ] Test Different Parameter Types
- [ ] Test URL parameters.
- [ ] Test POST body parameters.
- [ ] Test **cookies** by removing or modifying cookie values.
- [ ] Test **headers**.
- [ ] Look for Error messages or stack traces.
- [ ] Unexpected application behavior (e.g., bypassing authentication).
- [ ] Changes in application logic or flow.
- [ ] Missing or altered data in the response.
- [ ] Repeat the process for all relevant requests in the application.
### Insufficient workflow validation

- [ ] Identify the workflow being tested (e.g., purchase process, account creation, password reset).
- [ ] Map out the steps involved in the workflow.
- [ ] Observe the sequence of requests and responses:.
- [ ] Note any parameters that control the workflow.
- [ ] Check for any client-side validation or hidden parameters.
- [ ] Resend the request without completing the previous steps.
- [ ] Tamper with parameters.
- [ ] Test if the workflow can be bypassed or manipulated.
- [ ] Attempt to skip intermediate steps 
- [ ] Check if the workflow completes without proper validation
- [ ] Look for unexpected behavior or errors in the response.

### Authentication bypass via flawed state machine

- [ ] Map out the authentication process.
- [ ] Identify the sequence of requests and responses.
- [ ] Note any state-dependent steps.
- [ ] Intercept requests during the authentication process.
- [ ] Observe the flow.
- [ ] Check for any state tokens or session identifiers.
- [ ] Drop or tamper with the requests.
- [ ] Attempt to access restricted pages directly.
- [ ] Modify or remove state-dependent parameters.
- [ ] Check if the application enforces the correct state transitions.
- [ ] Observe if the application defaults to a privileged role when state validation is missing.
- [ ] Use content discovery tools to identify hidden or restricted paths.
- [ ] Attempt to access these paths directly after bypassing the state machine.
- [ ] Look for unexpected behavior or errors in the response.
- [ ] Test other authentication workflows for similar vulnerabilities.
### Infinite money logic flaw

### Authentication Bypass via Encryption Oracle
#### Initial Reconnaissance
- [ ] Identify authentication mechanisms on the target application
- [ ] Enable "Remember me" or "Stay logged in" features if available
- [ ] Capture and analyze all related cookies and session identifiers
- [ ] Examine the format and encoding of authentication cookies
- [ ] Test for reflection of input in error messages or responses
#### Encryption Oracle Identification
- [ ] Look for encrypted cookies in the application (Base64-encoded values are common)
- [ ] Find functionality that returns errors containing reflected user input
- [ ] Test input validation functions (especially email, username fields)
- [ ] Identify endpoints that process and reflect encrypted data
- [ ] Analyze error messages for cryptographic implementation details
#### Encryption/Decryption Testing
- [ ] Set up request sequences to:
- [ ] Encrypt arbitrary data via input fields
- [ ] Decrypt values via reflected error messages
- [ ] Determine the encryption algorithm used (block cipher vs stream cipher)
- [ ] Identify block size if using a block cipher (commonly 16 bytes for AES)
- [ ] Test for padding requirements and analyze padding errors
#### Cookie Structure Analysis
- [ ] Decrypt authentication cookies to understand their structure
- [ ] Identify components (username, timestamp, role, etc.)
- [ ] Determine format requirements for valid cookies
- [ ] Test validity periods or timestamp requirements
#### Exploitation Preparation
- [ ] Create crafted payloads with privileged user identifiers
- [ ] Handle any prefixes/suffixes added during encryption/decryption
- [ ] Calculate necessary padding to align with encryption block boundaries
- [ ] Test encryption/decryption of modified payloads
#### Circumvention Techniques
- [ ] Develop methods to remove unwanted prefixes from decrypted output
- [ ] Craft payloads that survive encryption/decryption cycles
- [ ] Prepare custom cookies with elevated privileges
- [ ] Test cookie manipulation techniques on non-critical endpoints
#### Access Verification
- [ ] Replace session cookies with crafted values
- [ ] Test access to privileged functions or admin areas
- [ ] Verify successful authentication as target user
- [ ] Document the vulnerability with proof of access
#### Security Report Documentation
- [ ] Document the encryption oracle vulnerability
- [ ] Capture complete HTTP request/response pairs
- [ ] Note specific headers, parameters, and cookies involved
- [ ] Provide clear reproduction steps
- [ ] Suggest remediation approaches for the vulnerability
### Email address parser discrepancies