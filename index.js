const {HarperDB} = require("node-harperdb")
const {check: type, assert} = require("type-approve")

const clamp = function(value, min = 0, max = 1) {
    return Math.min(Math.max(value, min), max)
}

const trimDecimals = function(number, length) {
    const expression = new RegExp('^-?\\d+(?:\.\\d{0,' + (length || -1) + '})?')
    return number.toString().match(expression)[0]
}

const parseInfinity = function(value) {
    switch(value.toString().toLowerCase()) {
        case "infinity": return Infinity
        case "-infinity": return -Infinity
        default: return value
    }
}

module.exports = settings => config.call(module.exports, settings)
module.exports.defend = (...params) => {
    if(!(module.exports.clients instanceof HarperDB
    && module.exports.requests instanceof HarperDB))
    {
        return config.apply(module.exports, params)
    }
    return middleware.apply(module.exports, params)
}
module.exports.attacks = require("./collection")
module.exports.Pattern = require("./attack")



const config = function(settings) {
    assert(
        type({object: settings})
        && type({
            object: settings.harperdb,
            strings: [
                settings.harperdb.instance,
                settings.harperdb.auth,
                settings.harperdb.schema
            ]
        })
        && type(
            {nil: settings.attempts},
            {integer: settings.attempts}
        ),
        "Malformed configuration!"
    )
    this.clients = new HarperDB(
        settings.harperdb.instance,
        settings.harperdb.auth,
        settings.harperdb.schema,
        "clients"
    )
    this.requests = new HarperDB(
        settings.harperdb.instance,
        settings.harperdb.auth,
        settings.harperdb.schema,
        "requests"
    )
    this.attempts = clamp(settings.attempts ?? 10, 1, Infinity)
    this.rate = clamp(settings.attempts ?? 12, 1, Infinity) // maximal count of request per hour
    this.decorator = "violation" // express request decorator name
    return this.defend
}



const middleware = async function(request, response, next) {
    const url = request.protocol + '://' + request.headers.host + request.originalUrl
    let violation = {intent: "GOOD"} // have faith in humanity... xD

    try {
        assert(
            type({nil: request[this.decorator]}),
            "Request decorator already occupied!"
        )
        assert(
            this.db instanceof HarperDB
            && type({
                integer: this.attempts,
                string: this.decorator
            }),
            "Missing configuration!"
        )

        request[this.decorator] = violation // add a new express request decorator

        for(const [name, attack] of this.attacks.entries()) {
            const patterns = attack.match(url)
            if(patterns.length > 0) {
                violation.name = name
                violation.patterns = patterns.map(regex => regex.toString())
                violation.intent = "EVIL" // ...sometimes humanity will still disappoint you.
                response.status(403) // well, then cut the ropes! (403 Access Forbidden)
                break
            }
        }
    } catch(error) {
        //response.status(500) // 500 Internal Server Error
        //return next(`Couldn't verify the intent of the request from ${request.ip} to ${request.method.toUpperCase()} ${url} because of: ${error.message}`)

        console.warn(`Couldn't verify the intent of the request from ${request.ip} to ${request.method.toUpperCase()} ${url} because of: ${error.message}`)
        return next()
    }

    try {
        // TODO fetch timestamps as well and calculate rate-limit: if too many requests then return 429 Too Many Requests status code!
        // TODO don't show blacklisted requests in logfile when threshold exeeded by more than 10x!

        const suspects = await this.clients.select({ip: request.ip})
        const attempts = await this.requests.select({ip: request.ip, intent: "EVIL"}, Math.max(this.attempts, this.rate))
        const observed = suspects.length > 0 || attempts.length > 0
        const blacklisted = observed ? suspects.some(client => client.blacklisted === true) : attempts.length >= this.attempts
        const whitelisted = observed ? suspects.some(client => client.whitelisted === true) : false
        const outpaced = attempts.filter(req => Date.now() / 1000 - req.__createdtime__ <= 3600).length >= this.rate

        //if(suspects.length > 1) {/*NOTICE: db has duplicates!*/}
        //if(blacklisted && whitelisted) {/*NOTICE: conflict (considered blacklisted)!*/}

        const query = await db.drain().catch(() => []) // siliently catch errors and convert response into an empty array!
        const record = Object.assign({}, ...query.flat())

        const observed = record.length > 0 // client is being observed (low severity)
        const attempts = record
            .map(req => parseInfinity(req.attempts))
            .reduce((sum, count) => sum + count, 0)
        const blacklisted = attempts >= this.attempts // attacker being observed (hight severity)

        if(violation.intent === "GOOD" && !blacklisted) {
            violation.attempts = attempts // show all previously/current recorded violations
            return next()
        }

        // NOTE: From here, the client has either a BAD intent or has already been blacklisted!
        response.status(403) // good becomes evil when blacklisted (403 Access Forbidden)

        const receipt = await this.db.upsert({
            ip: request.ip,
            intent: violation.intent,
            method: request.method,
            url: url,
            violations: violation.patterns, // object with attack name and attack patterns that match the request.originalUrl
            attempts: 1, // NOTE: Every request happens only ones! But in case you want to blacklist an IP manually, you can set this to larger than this.attempts in your database and the client will be blocked every time.
            headers: request.headers,
            payload: request.body
        })

        let notification = [
            `Detected suspicious request from ${request.ip} with ${violation.intent} intent.`,
            `Request to ${request.method.toUpperCase()} ${url} has been rejected!`
        ]
        if(blacklisted) {
            notification.push(
                `Client IP ${request.ip} is a well-known blacklist candidate and has already exceeded the blacklisting quota limits (max attempts: ${this.attempts}) by a factor of ${trimDecimals(attempts / this.attempts, 1)}x.`
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
        if(observed) notification.push(`Database record ${receipt.upserted_hashes.join(", ")} has been updated.`)
        else notification.push(`Database record ${receipt.upserted_hashes.join(", ")} has been created.`)

        return next(notification.join("\n"))

    } catch(error) {
        response.status(500) // 500 Internal Server Error
        return next(`Failed processing suspicious request from ${request.ip} to ${request.method.toUpperCase()} ${url} because of: ${error.message}`)
    }
}
