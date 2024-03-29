const {check: type, assert} = require("type-approve")

module.exports = class Attack {
    constructor(patterns) {
        if(!(this instanceof Attack)) return new Attack(patterns)
        this.add(patterns)
        return this
    }

    clear() {
        this.patterns = []
    }

    add(patterns) {
        assert(type({string: patterns}, {expression: patterns}, {array: patterns}), "Invalid patterns!")
        if(!type({array: this.patterns})) this.clear()
        for(const pattern of type({array: patterns}) ? patterns : [patterns]) {
            assert(type({string: pattern}, {expression: pattern}), `Malformed pattern: ${pattern}`)
            if(type({string: pattern})) {
                this.patterns.push(new RegExp(pattern.replace(/\W/g, "\\$&"), "i")) // escape special chars inside pattern
            } else {
                this.patterns.push(pattern) // Pattern could be passed straight into `new RegExp()` without typechecking but then flags like "gi" could be overridden by the default and mandatory flag "i"!
            }
        }
        return this
    }

    match(url) {
        assert(type({array: this.patterns}) && this.patterns.length > 0, "Missing patterns!")
        assert(type({string: url}) && url.length > 0, `Invalid url (${typeof url}): ${url}`)
        const path = new URL(url.toLowerCase(), "http://dummy.domain")
        let paths = [path.pathname + path.search]
        try {
            paths.push(decodeURI(paths[0])) // guard decodeURI because it could throw an error
        } catch(_) {
        }
        return this.patterns.filter(pattern => paths.some(pattern.test.bind(pattern)))
    }

    test(url) {
        return this.match(url).length > 0
    }
}
