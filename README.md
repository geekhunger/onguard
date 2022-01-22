# Readme

> **Important note:** This is a pre-release! I currently battle-test the code and (re)write this Readme. Please feel free to check this project out, play with it and add it to your watchlist! But please, do not use it in production just yet! (I'm working hard to finish it within the next couple days...)



<h2 align="center">What? Why?</h2>

<p align="center">
    I've recently dicovered <a href="https://www.npmjs.com/package/express-blacklist" target="_blank">express-blacklist</a> and <a href="https://www.npmjs.com/package/express-defend" target="_blank">express-defend</a>. I liked both packages. Unfortunately, they were abandoned a long time ago. There were many improvements that I've had on my mind... but most importantly, I wanted to use <a href="https://www.npmjs.com/package/node-harperdb target="_blank">node-harperdb</a> for blacklisting, instead of plain files!
</p>

<p align="center">
    <a href="https://www.npmjs.com/package/express-blacklist" target="_blank"><code>express-blacklist</code></a> + <a href="https://www.npmjs.com/package/express-defend" target="_blank"><code>express-defend</code></a> + <a href="https://www.npmjs.com/package/node-harperdb target="_blank"><code>node-harperdb</code></a> = <b><code>onguard</code></b>
</p>

<p align="center">
    Install this package from NPM: <code>npm i onguard</code><br>
    🤍
</p>



## Setup your defense

The `require("onguard")` statement returns a function which you must call with a `settings` object. The configuration function will then return an express middleware handler, which you plug into your application or your app router.

> There's actually more to it... Besides the config-function, the return value contains a `defend` method, an `attacks` Map and `Pattern` class. [But let's put it aside for now and expore it later in depth...](#suspicious-requests)

Here's a snippet to get you started. Use it to add a middleware to your `express` app instance or your `express.Router`.

```js
app.use(require("onguard")({ // `app` is your express application or an express.Router
    harperdb: {
        instance: "https://my-app.harperdb.io...",
        auth: "b64Ba$ic4ut#Htoken=",
        schema: "my_app", // default is "onguard"
        table: "violent_requests" // default is "malicious"
    }
}))
```

> See [node-harperdb](https://www.npmjs.com/package/node-harperdb) for more information about the `harperdb: {}` config object (which is identical to this the constructor in the `HarperDB` class).

**The above example is everything you need to use 'onguard' in your project!** But you can customize the settings further, if you want. You can also extend the preset rules for validating a reqests, by literal- or regex expressions. (We will explore this topic later.)

You can also assign the configuration function from the `require` call to a variable and create your defense middleware later.

```js
const defend = require("onguard")

// ... do whatever ...

app.use(defend({
    // Value of 1 will block client ip immideatelly uppon first suspicious request!
    // Default value is 10
    attempts: 3,
    
    // Adds a new ExpressJS Request decorator with custom name.
    // For example: request.evil = {name, patterns}
    // Default value is "attack"
    decorator: "evil",

    // An instanceof HarperDB of an object with HarperDB credentials (mandatory)
    harperdb: {
        instance: "...",
        auth: "..."
    }
}))
```

**If you have configured HarperDB connection already** and want to use *that* connection object, then you can simply pass it directly to the `harperdb` property...

> **But, be careful with that!** It will use the *currently connected database table, and will polute it* with entries of blacklisted client requests!

```js
const {database} = require("node-harperdb")
const db = database(
    "https://my-blog.harperdb.io...",
    "auth-key...",
    "my-blog",
    "posts"
)

// ... do something with the "blog" table ...

const defend = require("onguard")

/*
    IMPORTANT:
    Verify (and change if needed) the table your current HarperDB connection instance!
    Do not risk poluting this table with entries from this package!
*/
db.table = "blacklisted-requests" // change the table name of current db connection

app.use(defend({ // setup onguard and use it with current db connection
    attempts: 5,
    harperdb: db
}))
```

<b id="attempts-count">Choose a reasonable number for the `attempts` count!</b>

The default value is `10`. Keeping it at a low value, allows you to blacklist suspicious requests faster, but a low value could be too restrictive for some applications.

Keep in mind, that not every client should be blacklisted immideately for making malicious requests to your application, because the client could have picked-up a bad link somewhere on the internet by accident. Or, he could be a victim to a 'man-in-the-middle' attack himself. (Attacking request was made through this client, by an attacker that uses this client's machine to make bad requests to your app on his behalf.)

You should set the `attempts` parameter to a value that . because client may just fallow a redirected link or picks it up by accident somewhere and you will blacklist him on first (unknown) attack!





## How it works...

Make sure to call the 'onguard' middleware *as early as possible* in your application middleware chain!

When you now run your ExpressJS application, then each client request will flow through the 'onguard' middleware. 'onguard' will check the requesting client and the requested URL.

- If it doesn't find anything "suspicious" about the request, then the request is passed onto the `next()` handler of your middleware chain. (As if 'onguard' wasn't there.)
- [If 'onguard' detects that the client is trying to attack or abuse your application](#suspicious-requests) by calling malicious URLs on your app, then it will mark this request as "evil"!

> A request may also be *not* classified as "evil" but it could still come from an IP that has become conspicuous in the past (or is even already 'truly blacklisted').<br>
> ([An IP becomes 'truly blacklisted' only after exeeding the quota limit](#attempts-count) of `attempts`, that you have defined during your configuration.)<br>
> Anyways, blacklisted clients and evil requests will both be rejected by the 'onguard' middleware!

"Suspicious" requests will be tracked: The IP of the requesting client will be saved into the database (if it isn't yet), and related database entries gets updated (for example with a fresh attempts count).

> For "suspicious" requests, there will be a special express request decorator (whose name you can change by setting the `decorator` parameter in your config). For example:
>
> ```js
> // somewhere AFTER the 'onguard' middleware...
> app.use(function(request, response, next) {
>     console.log(request.attack)
>     // returns:
>     /*{
>         name: "ReflectedXSS",
>         patterns: [
>             "/node_modules"
>         ]
>     }*/
> })
> ```

**An evil request *should* be rejected immideatelly!** - But 'onguard' doesn't just decide to quietly drop the request! *Instead,* it sets the `response.statusCode` to `403 Forbidden` and passes the request to your `next("Response rejected!")` error handler! - You decide how to respond!

**This behaviour gives you maximal control over the response!** (And this is also the most 'vanilla' way of handling exceptions in ExpressJS! No callback-hell anymore.)

You could create an error handler just after the 'onguard' middleware function, to specifically catch and handle "evil" client requests, rejected by 'onguard'... But you could also let the error hit your default `404 Not Found` error handler, if you want. (You know, that everyone should have a final error handler in their middleware chain, right? One last function that catches all the errors in your app and responds with a sane message to the client. [If you don't, then please, do yourself a favor and read this!](http://expressjs.com/en/guide/error-handling.html#the-default-error-handler))

```js
const {catfile} = require("fopsy") // NPM package
const credentials = catfile("./blacklist.json")[0] // HarperDB connection object stored as JSON file
const defend = require("onguard") // this NPM package
let app = require("express")() // ExpressJS application instance

app.use(defend({
    attempts: 10,
    decorator: "badclient",
    harperdb: JSON.parse(credentials.content)
}))

app.use(function(error, request, response, next) { // onguard blacklist handler!!!
    //response.status(404) // default status is 403. Want to change it?
    //response.send(error) // detailed error message from onguard (Probably not a good idea to present the blacklisted client with it!)

    // instead, you could console.log this detailed error message
    // or you could use a dedicated file logger of your choice to log this event...
    console.log(error)

    // or you can build your own log message...
    // here are a couple useful variales that you could use:

    const intent = request.badrequest === undefined ? "good" : "bad"
    console.info(`Rejected request had generally a ${intent} intent...`)

    if(request.badrequest !== undefined) {
        console.log("Detected attack:", request.badrequest.name)
        console.log("Attack was detected by patterns:", request.badrequest.name)
        console.log("Request method:", request.method)
        console.log("Request url:", request.originalUrl)
    }

    console.log("Suspicious client IP:", request.ip)

    // respond to the client with the default 403 status code and a customized message
    response.send("Dear visitor, your request is malformed!")
    
    // You could also call `next(error)` or `next("custom error message")`
    // and let this middleware fall-through directly into your default error handler!
})

app.get("/", function(request, response, next) {
    response.send("Welcome, visitor!")
})

app.use(function(error, request, response, next) { // your default error handler
    response.status(404).send(error)
    next()
})

app.listen()
```

Well, that's about it! Good requests go through normally. Bad requests throw an error and will end up in one of your error handlers.




<h2 id="suspicious-requests">TODO</h2>

*I'm working hard on testing code and writing the docs. Please, give me a moment to finish it...*

- Suspicious requests:
    - What does 'onguard' understand as <i>attacks</i>?
    - How do they work internally?
    - How do you define your own attack (RegExp `Pattern` rule)?
    - How do you override the `attacks` preset? (What about clearing all?)
- How to add IP to blacklist manually?
