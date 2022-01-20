const {HarperDB} = require("node-harperdb")
const {check: type, assert} = require("type-approve")


module.exports = (...settings) => config.apply(module.exports, settings)
module.exports.defend = (...params) => middleware.apply(module.exports, params)
module.exports.attacks = require("./collection")
module.exports.Pattern = require("./attack")


const config = function(settings) {
    assert(
        type({object: settings})
        && type({object: settings.harperdb})
        && type({strings: [
            settings.harperdb.instance,
            settings.harperdb.auth,
            settings.harperdb.schema,
            settings.harperdb.table
        ]})
        && type(
            {nil: settings.attempts},
            {integer: settings.attempts}
        ),
        "Malformed configuration!"
    )
    this.db = new HarperDB(
        settings.harperdb.instance,
        settings.harperdb.auth,
        settings.harperdb.schema ?? "onguard",
        settings.harperdb.table ?? "blacklist"
    )
    this.attempts = settings.attempts ?? 1
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
        
        let blacklisted = await db.select({ip: request.ip})
        const evil = !type({nil: request[this.settings.decorator]})

        if(evil && blacklisted.length === 0) {
            blacklisted.push({
                ip: request.ip,
                attempts: 0,
                requests: [],
                attacks: []
            })
        }

        for(let id = 0; id < blacklisted.length; id++) { // NOTE: Normally, there's only a single record inside the blacklist, but we are prepared to handle duplicate records too!
            let suspect = blacklisted[id]
            suspect.attempts++
            suspect.requests.push({
                method: request.method,
                url: request.originalUrl,
                headers: request.headers,
                body: request.body
            })
            suspect.attacks.push(
                request[this.settings.decorator]
            )
        }

        if(blacklisted.length > 0) { // evil suspects are included in blacklist
            await db.upsert(blacklisted)
            const attempts = blacklisted
                .map(elem => elem.attempts)
                .reduce((prev, curr) => (prev || 0) + (curr || 0), 0)
            const error = [
                `Request to ${request.method.toUpperCase()} ${request.originalUrl} has been rejected!`,
                `IP ${request.ip} has been blocked`,
                attempts > this.attempts ? `after exeeding ${attempts} attempts!` : "!"
            ]
            return next(error.join(" "))
        }
    } catch(error) {
        response.status(500) // Internal Server Error
        return next(`Request to ${request.method.toUpperCase()} ${request.originalUrl} has been rejected: ${error}`)
    }
    next()
}

