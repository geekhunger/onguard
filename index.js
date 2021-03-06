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
    if(!(module.exports.db instanceof HarperDB)) {
        return config.apply(module.exports, params)
    }
    return middleware.apply(module.exports, params)
}
module.exports.attacks = require("./collection")
module.exports.Pattern = require("./attack")



const config = function(settings) {
    assert(
        type({object: settings})
        && (settings.harperdb instanceof HarperDB || (
            type({object: settings.harperdb})
            && type({strings: [
                settings.harperdb.instance,
                settings.harperdb.auth
            ]})
        ))
        && type(
            {nil: settings.attempts},
            {integer: settings.attempts}
        ),
        "Malformed configuration!"
    )
    if(settings.harperdb instanceof HarperDB) {
        this.db = settings.harperdb
    } else {
        this.db = new HarperDB(
            settings.harperdb.instance,
            settings.harperdb.auth,
            settings.harperdb.schema ?? "onguard",
            settings.harperdb.table ?? "watchlist"
        )
    }
    this.status = type({number: settings.status}) ? settings.status : 403 // 403 Access Forbidden
    this.attempts = clamp(settings.attempts ?? 10, 1, Infinity)
    this.decorator = "violation" // express request decorator name
    return this.defend
}



const middleware = async function(request, response, next) {
    const complete_url = request.protocol + '://' + request.headers.host + request.originalUrl
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
            const patterns = attack.match(complete_url)
            if(patterns.length > 0) {
                violation.name = name
                violation.patterns = patterns.map(regex => regex.toString())
                violation.intent = "EVIL" // ...sometimes humanity will still disappoint you.
                response.status(this.status) // well, then cut the ropes!
                break
            }
        }
    } catch(error) {
        //response.status(500) // 500 Internal Server Error
        //return next(`Couldn't verify the intent of the request from ${request.ip} to ${request.method.toUpperCase()} ${complete_url} because of: ${error.message}`)

        console.warn(`Couldn't verify the intent of the request from ${request.ip} to ${request.method.toUpperCase()} ${complete_url} because of: ${error.message}`)
        return next()
    }

    try {
        const watchlist = await this.db.run(`
            select attempts
            from ${this.db.schema}.${this.db.table}
            where ip = '${request.ip}'
        `).catch(() => []) // siliently catch errors and return an empty array!

        const observed = watchlist.length > 0 // client is being observed (low severity)
        const attempts = watchlist
            .map(req => parseInfinity(req.attempts))
            .reduce((sum, count) => sum + count, 0)
        const blacklisted = attempts >= this.attempts // attacker being observed (hight severity)

        if(violation.intent === "GOOD" && !blacklisted) {
            violation.attempts = attempts // show all previously/current recorded violations
            return next()
        }

        // NOTE: From here, the client has either a BAD intent or has already been blacklisted!
        response.status(this.status) // good becomes evil when blacklisted

        const receipt = await this.db.upsert({
            ip: request.ip,
            intent: violation.intent,
            method: request.method,
            url: complete_url,
            violations: violation.patterns, // object with attack name and attack patterns that match the request.originalUrl
            attempts: 1, // NOTE: Every request happens only ones! But in case you want to blacklist an IP manually, you can set this to larger than this.attempts in your database and the client will be blocked every time.
            headers: request.headers,
            payload: request.body
        })

        let notification = [
            `Detected suspicious request from ${request.ip} with ${violation.intent} intent.`,
            `Request to ${request.method.toUpperCase()} ${complete_url} has been rejected!`
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
        return next(`Failed processing suspicious request from ${request.ip} to ${request.method.toUpperCase()} ${complete_url} because of: ${error.message}`)
    }
}
