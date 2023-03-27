const {HarperDB} = require("node-harperdb")
const {check: type, assert} = require("type-approve")


const validateUrl = function(path) {
    for(let [name, attack] of this.attacks.entries()) {
        if(!type({expression: attack}) && type({string: attack})) {
            attack = new RegExp(attack, "i")
        }
        let patterns = attack.match(path) // .match() is a method of the Attack class
        if(patterns.length > 0) {
            return {name, patterns}
        }
    }
}


const clampNumber = function(value, min = 0, max = 1) {
    return Math.min(Math.max(value, min), max)
}


const parseInfinity = function(value) {
    switch(value?.toString()?.toLowerCase()) {
        case "∞":
        case "inf":
        case "infinity": return Infinity
        case "-∞":
        case "-inf":
        case "-infinity": return -Infinity
        default: return undefined
    }
}


module.exports = settings => config.call(module.exports, settings)

module.exports.defend = (...params) => {
    if(!(module.exports.clients instanceof HarperDB && module.exports.requests instanceof HarperDB)) {
        return config.apply(module.exports, params)
    }
    return middleware.apply(module.exports, params)
}

module.exports.attacks = require("./collection")
module.exports.Pattern = require("./attack")

console.log(module.exports.attacks)


const config = function(settings) {
    assert(
        type({object: settings}) &&
        type({
            object: settings.harperdb,
            strings: [
                settings.harperdb.instance,
                settings.harperdb.auth,
                settings.harperdb.schema
            ]
        }) &&
        type(
            {nil: settings.attempts},
            {integer: settings.attempts}
        ),
        "Malformed configuration!"
    )
    this.clients = new HarperDB(
        settings.harperdb.instance,
        settings.harperdb.auth,
        settings.harperdb.schema,
        "onguard_clients"
    )
    this.clients.primary_key = "ip"
    this.requests = new HarperDB(
        settings.harperdb.instance,
        settings.harperdb.auth,
        settings.harperdb.schema,
        "onguard_requests"
    )
    this.attempts = clampNumber(settings.attempts ?? 10, 1, Infinity)
    this.rate = clampNumber(settings.attempts ?? 12, 1, Infinity) // maximal count of request per hour
    this.decorator = "violation" // express request decorator name
    return this.defend
}


const suspiciousUserAgent = function() {
}


const middleware = async function(request, response, next) {
    const url = request.protocol + '://' + request.headers.host + request.originalUrl
    let violation = {intent: "GOOD"} // have faith in humanity ;D

    if(!req.headers["user-agent"] || !/^[a-zA-Z0-9\s\.\-_]+$/.test(req.headers["user-agent"])) { // suspicious user agent
    }

    try {
        assert(
            type({nil: request[this.decorator]}),
            "Request decorator already occupied!"
        )
        assert(
            this.clients instanceof HarperDB &&
            this.requests instanceof HarperDB &&
            type({integer: this.attempts, string: this.decorator}),
            "Missing configuration!"
        )

        request[this.decorator] = violation // add a new express request decorator

        const attack = validateUrl.call(this, url)
        if(type({object: attack})) {
            violation.name = attack.name
            violation.patterns = attack.patterns.map(rule => rule.toString()) // typecast RegExp into a string
            violation.intent = "EVIL" // sometimes humanity will still disappoint you -_-
            response.status(403) // cut the ropes (403 Access Forbidden)
        }
    } catch(error) {
        const msg = `Couldn't verify the intent of the request from ${request.ip} to ${request.method.toUpperCase()} ${url}! ${error.message}`
        console.warn(msg)
        //response.status(500) // 500 Internal Server Error
        //return next(msg)
        return next()
    }

    try {
        // TODO fetch timestamps as well and calculate rate-limit: if too many requests then return 429 Too Many Requests status code!
        // TODO don't show blacklisted requests in logfile when threshold exeeded by more than 10x!

        const clients = await this.clients.select({ip: request.ip})
        const requests = await this.requests.select({client: request.ip, intent: "EVIL"}, Math.max(this.attempts, this.rate))

        const query = await this.requests.drain().catch(() => []) // siliently catch errors and convert response into an empty array!
        const records = Object.assign({}, ...query.flat())

        //if(clients.length > 1) {/*NOTICE: db has duplicates!*/}
        //if(blacklisted && whitelisted) {/*NOTICE: conflict (considered blacklisted)!*/}

        const attempts = records
            .map(req => parseInfinity(req.attempts))
            .reduce((sum, count) => sum + count, 0)

        const observed = records.length > 0 // client is being observed (low severity)

        const blacklisted = attempts >= this.attempts // attacker being observed (hight severity)
        //const blacklisted = observed ? clients.some(client => client.blacklisted === true) : requests.length >= this.attempts
        //const whitelisted = observed ? clients.some(client => client.whitelisted === true) : false

        const limitbreach = requests.filter(req => Date.now() / 1000 - req.__createdtime__ <= 3600).length >= this.rate

        if(violation.intent.match(/GOOD/i) && !blacklisted) {
            violation.attempts = attempts // show all previously/current recorded violations
            return next()
        }

        // NOTE: From here, the client has either a BAD intent or has already been blacklisted!
        response.status(403) // good becomes evil when blacklisted (403 Access Forbidden)

        const receipt = await this.requests.upsert({
            client: request.ip,
            intent: violation.intent.toUpperCase(),
            method: request.method.toUpperCase(),
            url: url,
            params: req.query,
            headers: request.headers,
            payload: request.body,
            violations: violation.patterns, // object with attack name and attack patterns that match the request.originalUrl
        })

        let notification = [
            `Detected suspicious request from ${request.ip} with ${violation.intent} intent.`,
            `Request to ${request.method.toUpperCase()} ${url} has been rejected!`
        ]

        if(blacklisted) {
            notification.push(
                `Client IP ${request.ip} is a well-known blacklist candidate and has already exceeded the blacklisting quota limits (max attempts: ${this.attempts}) by a factor of ${parseFloat(attempts / this.attempts).toFixed(1)}x.`
            )
        } else if(attempts > 1) {
            notification.push(
                `Client IP ${request.ip} is a known suspect and has been blocked ${attempts}x so far.`
            )
            if(observed) {
                notification.push(
                    `(${this.attempts - attempts} attempts left until client becomes blacklisted!)`
                )
            }
        }

        if(observed) {
            notification.push(`Database record ${receipt.upserted_hashes.join(", ")} has been updated.`)
        } else {
            notification.push(`Database record ${receipt.upserted_hashes.join(", ")} has been created.`)
        }

        return next(notification.join("\n"))

    } catch(error) {
        response.status(500) // 500 Internal Server Error
        return next(`Failed processing suspicious request from ${request.ip} to ${request.method.toUpperCase()} ${url} because of: ${error.message}`)
    }
}
