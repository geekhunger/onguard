const {HarperDB} = require("node-harperdb")
const {check: type, assert} = require("type-approve")

const trimDecimals = function(number, length) {
    const expression = new RegExp('^-?\\d+(?:\.\\d{0,' + (length || -1) + '})?')
    return number.toString().match(expression)[0]
}

const ordinalCount = function(i) {
    let j = i % 10
    let k = i % 100
    if(j == 1 && k != 11) return i + "st"
    if(j == 2 && k != 12) return i + "nd"
    if(j == 3 && k != 13) return i + "rd"
    return i + "th"
}


module.exports = (...settings) => config.apply(module.exports, settings)
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
                settings.harperdb.auth,
                settings.harperdb.schema,
                settings.harperdb.table
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
            settings.harperdb.table ?? "blacklist"
        )
    }
    this.attempts = Math.max(1, settings.attempts ?? 3) // value with lower-clamp!
    this.decorator = "attack" // express request decorator
    return this.defend
}


const middleware = async function(request, response, next) {
    try {
        assert(
            this.db instanceof HarperDB
            && type({
                integer: this.attempts,
                string: this.decorator
            }),
            "Missing settings!"
        )
        assert(
            type({nil: request[this.settings.decorator]}),
            "Request decorator already occupied!"
        )
        for(const [name, attack] of this.attacks.entries()) {
            const patterns = attack.match(request.originalUrl)
            if(patterns.length > 0) {
                request[this.settings.decorator] = {name, patterns} // express request decorator
                response.status(403) // Access Forbidden
                break
            }
        }
    } catch(error) {
        response.status(500) // Internal Server Error
        return next(`Couldn't verify the intent of the request from ${request.ip} to ${request.method.toUpperCase()} ${request.originalUrl} because of: ${error}`)
    }
    try {
        let suspects = await db.select({ip: request.ip})
        const evil = !type({nil: request[this.settings.decorator]})

        if(suspects.length > 1) {
            // Merge duplicate records of the same client...
            // NOTE: Normally, there's only one single record inside the blacklist, but we are prepared to handle duplicate records too!
            suspects = {
                ip: request.ip,
                attempts: suspects
                    .map(entry => entry.attempts || 0)
                    .reduce((sum, count) => sum + count, 0),
                requests: suspects
                    .map(entry => entry.requests) // array of objects
                    .flat(1),
                attacks: suspects
                    .map(entry => entry.attacks) // array of regex patterns
                    .flat(1)
            }
        }

        if(suspects.length === 0 && evil) {
            suspects.push({ // prepare new entry for the database
                ip: request.ip,
                attempts: 0,
                requests: [],
                attacks: []
            })
        }

        if(suspects.length === 1) {
            let client = suspects[0]
            client.attempts++
            client.requests.push({
                intent: evil ? "bad" : "good",
                method: request.method,
                url: request.originalUrl,
                headers: request.headers,
                body: request.body
            })
            client.attacks.push(
                request[this.settings.decorator] // object with attack name and attack patterns that match the request.originalUrl
            )
            const transaction = await db.upsert(client)

            let notification = [
                `Detected suspicious request from ${request.ip}, with ${client.requests[client.requests.length].intent} intent.`,
                `Request to ${request.method.toUpperCase()} ${request.originalUrl} has been rejected!`
            ]
            if(client.attempts >= this.attempts) {
                notification.push(
                    `Client IP ${request.ip} is a well-known suspect and has already exceeded the blacklisting quota limits (max attempts: ${this.attempts}) by a factor of ${trimDecimals(client.attempts / this.attempts, 1)}x.`
                )
            } else if(client.attempts > 1) {
                notification.push(
                    `Client IP ${request.ip} a known suspect and has been blocked for the ${ordinalCount(client.attempts)} time.`
                )
                if(client.attempts > 0) {
                    notification.push(
                        `(${this.attempts - client.attempts} attempts left until client becomes blacklisted.)`
                    )
                }
            }
            notification.push(
                `Database record ${transaction.upserted_hashes[0]} has been updated.`
            )

            return next(notification.join("\n"))
        }
    } catch(error) {
        response.status(500) // Internal Server Error
        return next(`Failed processing a suspicious request from ${request.ip} to ${request.method.toUpperCase()} ${request.originalUrl} because of: ${error}`)
    }
    next()
}

