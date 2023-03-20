// NOTE: RegExp rules will remain untouched. String rules will be converted into valid RegExp and become case-insensitive automatically!

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
    /SELECT [a-z0-9\s\*,"'] FROM/i,
]))

collection.set("ReflectedXSS", new Attack([
    "<script",
    "\\x3cscript",
    "%3cscript",
    "javascript:",
    "jav&#x0D;ascript:",
    "java\0script",
    "document.write",
    /(alert|eval|function|settimeout|setinterval)\(/i,
    /(onclick|onerror|onkeydown|onkeypress|onkeyup|onmouseout|onmouseover|onmouseout|onload)=/i,
    ".addeventlistener",
    "document.cookie",
]))

collection.set("PathTraversal", new Attack([
    "\\windows\\system32\\drivers\\etc\\hosts",
    "Windows\\System32\\cmd.exe",
    "Windows/System32/cmd.exe",
    "/wp-includes",
    "/.git",
    "/node_modules",
    "/dev/null",
    "/dev/random",
    "/cgi-bin",
    "/var/opt",
    "/bin/sh",
    "/etc/issue",
    "/etc/shadow",
    "/etc/hosts",
    "/etc/passwd",
    "c+dir+c:\\",
    "/stalker_portal",
    "microsoft.exchange.ediscovery.exporttool.application",
    "Autodiscover.xml",
    "?XDEBUG_SESSION_START=phpstorm",
    /\.+[\/\\]+/, // ./ | ..\\ | ./////\/\/ | ..//
    /[\/\\]{2,}/, // \\\ | //// | //
    /\.*%\d+[a-z]*\.*/i, // ..%00 | %2C. | ..%3fac
    /%+[a-z]%+/i, // %unfeudalize%
    /\w+.php/i, // config.inc.php | xmlrpc.php | index.php?filter= | PHP/eval-stdin.php | wp-login.php
    /\/owa\/auth\/\w+\.(js|aspx)/i, // /owa/logon/x.js
    /\.aspx\?[a-z]+=/i,
    /\.well\-known\/.*\/?[a-z]+\.txt$/i,
    /\/\.[\da-z\-_]+$/i, // /.env | /.hidden | /sitemap//.secret
    /invoke[\-_]?fun|function|[\W]*call[\W]\w+/i, // invokefunction | &function=call_user_func_array
    /&?[a-z]+(\[\d*\])+=/i, // &vars[1][]=HelloThinkPHP21 | &vars[0]=md5
]))
