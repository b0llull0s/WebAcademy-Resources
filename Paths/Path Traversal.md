- Path traversal is also known as directory traversal
- These vulnerabilities enable an attacker to read arbitrary files on the server that is running an application.
- This might include:

	- Application code and data.
	- Credentials for back-end systems.
	- Sensitive operating system files.

- In some cases, an attacker might be able to write to arbitrary files on the server, allowing them to modify application data or behaviour, and ultimately take full control of the server.
# Reading arbitrary files via path traversal

- The sequence `../` is valid within a file path, and means to step up one level in the directory structure.

```
https://insecure-website.com/loadImage?filename=../../../etc/passwd
```

- The three consecutive `../` sequences step up from `/var/www/images/` to the filesystem root, and so the file that is actually read is:

```
/etc/passwd
```

- On Windows, both `../` and `..\` are valid directory traversal sequences.
- The following is an example of an equivalent attack against a Windows-based server:
```
https://insecure-website.com/loadImage?filename=..\..\..\windows\win.ini
```

# Common obstacles to exploiting path traversal vulnerabilities

- You might be able to use an absolute path from the filesystem root, such as `filename=/etc/passwd`, to directly reference a file without using any traversal sequences.
- You might be able to use nested traversal sequences, such as `....//` or `....\/`. These revert to simple traversal sequences when the inner sequence is stripped
- In some contexts, such as in a URL path or the `filename` parameter of a `multipart/form-data` request, web servers may strip any directory traversal sequences before passing your input to the application. You can sometimes bypass this kind of sanitization by URL encoding, or even double URL encoding, the `../` characters. This results in `%2e%2e%2f` and `%252e%252e%252f` respectively. Various non-standard encodings, such as `..%c0%af` or `..%ef%bc%8f`, may also work
- An application may require the user-supplied filename to start with the expected base folder, such as `/var/www/images`. In this case, it might be possible to include the required base folder followed by suitable traversal sequences. For example: `filename=/var/www/images/../../../etc/passwd`
- An application may require the user-supplied filename to end with an expected file extension, such as `.png`. In this case, it might be possible to use a null byte to effectively terminate the file path before the required extension. For example: `filename=../../../etc/passwd%00.png`
# How to prevent a path traversal attack

- The most effective way to prevent path traversal vulnerabilities is to avoid passing user-supplied input to filesystem APIs altogether. Many application functions that do this can be rewritten to deliver the same behavior in a safer way.

- If you can't avoid passing user-supplied input to filesystem APIs, we recommend using two layers of defense to prevent attacks:

- Validate the user input before processing it. Ideally, compare the user input with a whitelist of permitted values. If that isn't possible, verify that the input contains only permitted content, such as alphanumeric characters only.
- After validating the supplied input, append the input to the base directory and use a platform filesystem API to canonicalize the path. Verify that the canonicalized path starts with the expected base directory.

Below is an example of some simple Java code to validate the canonical path of a file based on user input:

```
File file = new File(BASE_DIRECTORY, userInput); if (file.getCanonicalPath().startsWith(BASE_DIRECTORY)) { // process file }
```
