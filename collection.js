const Attack = require("./attack")
let collection = module.exports = new Map()

collection.set("SQLInjection", new Attack([
    "' or '1'='1",
    "or 'x'='x'",
    "or 1=1",
    '" or "1"="1',
    '" or ""=""',
    "' or ''=''",
    "DROP TABLE",
    "INSERT INTO",
]))

collection.set("ReflectedXSS", new Attack([
    "<script",
    "\\x3cscript",
    "%3cscript",
    "alert(",
    "onclick=",
    "onerror=",
    "onkeydown=",
    "onkeypress=",
    "onkeyup=",
    "onmouseout=",
    "onmouseover=",
    "onload=",
    "document.cookie",
    ".addeventlistener",
    "javascript:",
    "jav&#x0D;ascript:",
    "java\0script",    
]))

collection.set("PathTraversal", new Attack([
    "\\windows\\system32\\drivers\\etc\\hosts",
    "Windows\\System32\\cmd.exe",
    "Windows/System32/cmd.exe",
    "Autodiscover.xml",
    "/wp-includes",
    "/node_modules",
    "/cgi-bin",
    "/var/opt",
    "/bin/sh",
    "/etc/issue",
    "/etc/shadow",
    "/etc/hosts",
    "/etc/passwd",
    "c+dir+c:\\",
    "?XDEBUG_SESSION_START=phpstorm",
    /\.+[\/\\]+/, // ./ | ..\\ | ./////\/\/ | ..//
    /[\/\\]{2,}/, // \\\ | //// | //
    /\.*%\d+[a-z]*\.*/i, // ..%00 | %2C. | ..%3fac
    /%+[a-z]%+/i, // %unfeudalize%
    /\/\.[\da-z\-_]+$/i, // /.env | /.hidden | /sitemap//.secret
    /\.aspx\?[a-z]+=/i,
    /\.well\-known\/.*\/?[a-z]+\.txt$/i,
    /\w+.php/i, // config.inc.php | xmlrpc.php | index.php?filter= | PHP/eval-stdin.php | wp-login.php
    /invoke[\-_]?fun|function|[\W]*call[\W]\w+/i, // invokefunction | &function=call_user_func_array
    /&?[a-z]+(\[\d*\])+=/i, // &vars[1][]=HelloThinkPHP21 | &vars[0]=md5
]))
