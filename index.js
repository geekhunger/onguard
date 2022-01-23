const {HarperDB} = require("node-harperdb")
const {check: type, assert} = require("type-approve")

const clamp = function(value, min = 0, max = 1) {
    return Math.min(Math.max(value, min), max)
}

const trimDecimals = function(number, length) {
    const expression = new RegExp('^-?\\d+(?:\.\\d{0,' + (length || -1) + '})?')
    return number.toString().match(expression)[0]
}

const ordinalCount = function(i) { // 1st, 2nd, 3rd, 4th...
    let j = i % 10
    let k = i % 100
    if(j == 1 && k != 11) return i + "st"
    if(j == 2 && k != 12) return i + "nd"
    if(j == 3 && k != 13) return i + "rd"
    return i + "th"
}


module.exports = settings => config.call(module.exports, settings)
module.exports.defend = (...params) => middleware.apply(module.exports, params)
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
    this.attempts = clamp(settings.attempts ?? 10, 1, Infinity)
    this.decorator = "violation" // express request decorator name
    return this.defend
}


const middleware = async function(request, response, next) {
    assert(
        type({nil: request[this.decorator]}),
        "Request decorator already occupied!"
    )

    let violation = request[this.decorator] = { // add a new express request decorator
        intent: "GOOD" // have faith in humanity... xD
    }

    try {
        assert(
            this.db instanceof HarperDB
            && type({
                integer: this.attempts,
                string: this.decorator
            }),
            "Missing configuration!"
        )
        for(const [name, attack] of this.attacks.entries()) {
            const patterns = attack.match(request.originalUrl)
            if(patterns.length > 0) {
                violation.name = name
                violation.patterns = patterns.map(regex => regex.toString())
                violation.intent = "EVIL" // ...sometimes they will still disappoint you
                response.status(403) // well, then cut the ropes! (403 Access Forbidden)
                break
            }
        }
    } catch(error) {
        response.status(500) // 500 Internal Server Error
        return next(`Couldn't verify the intent of the request from ${request.ip} to ${request.method.toUpperCase()} ${request.originalUrl} because of: ${error.message}`)
    }

    try {
        // TODO keep footprint low when exchanging data with the database! (For example: 'Select' only ip and attempts! 'Insert' only id, attempts, requests and attacks - merge existing requests and attacks via SQL + JSONata queries at HarperDB!)

        let suspects = await this.db.select({ip: request.ip})
        
        assert(
            suspects.length < 2,
            `Database '${this.db.schema + "." + this.db.table}' must not contain more than 1 entry for the same client! (Found ${suspects.length} records for IP ${request.ip}! Please resolve merge conflicts in database table '${this.db.table}'.)`
        )

        const observed = suspects.length > 0 // low severity
        const blacklisted = observed && suspects[0].attempts >= this.attempts // hight severity

        if(violation.intent === "GOOD" && !blacklisted) {
            violation.attempts = observed ? suspects[0].attempts : 0 // show all previously recorded attempts
            return next()
        }

        // NOTE: From here, the client has either a BAD intent or has already been blacklisted!

        if(!observed) suspects.push({ip: request.ip}) // add client to watchlist (prepare new db entry)

        let client = suspects[0]
        if(type({nil: client.attempts})) client.attempts = 0
        if(type({nil: client.attacks})) client.attacks = []
        if(type({nil: client.requests})) client.requests = []

        client.attempts++
        client.attacks.push(violation) // object with attack name and attack patterns that match the request.originalUrl
        client.requests.push({
            intent: violation.intent,
            method: request.method,
            url: request.originalUrl,
            headers: request.headers,
            body: request.body,
            timestamp: Date.now()
        })
        
        const transaction = await this.db.upsert(client)

        let notification = [
            `Detected suspicious request from ${request.ip} with ${violation.intent} intent.`,
            `Request to ${request.method.toUpperCase()} ${request.originalUrl} has been rejected!`
        ]

        if(client.attempts >= this.attempts) {
            notification.push(
                `Client IP ${request.ip} is a well-known blacklist candidate and has already exceeded the blacklisting quota limits (max attempts: ${this.attempts}) by a factor of ${trimDecimals(client.attempts / this.attempts, 1)}x.`
            )
        } else if(client.attempts > 1) {
            notification.push(
                `Client IP ${request.ip} is a known suspect and has been blocked ${client.attempts}x so far.`
            )
            if(client.attempts > 0) {
                notification.push(
                    `(${this.attempts - client.attempts} attempts left until client becomes blacklisted!)`
                )
            }
        }

        if(observed) notification.push(`Database record ${transaction.upserted_hashes[0]} has been updated.`)
        else notification.push(`Database record ${transaction.upserted_hashes[0]} has been created.`)

        return next(notification.join("\n"))

    } catch(error) {
        response.status(500) // 500 Internal Server Error
        return next(`Failed processing a suspicious request from ${request.ip} to ${request.method.toUpperCase()} ${request.originalUrl} because of: ${error.message}`)
    }
}
