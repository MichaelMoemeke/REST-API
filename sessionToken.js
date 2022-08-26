const jwt = require("jsonwebtoken")

let sessionTokens = []

function generateSessionToken (user) {
    const sessionToken = jwt.sign(user, process.env.SESSION_TOKEN_SECRET, {expiresIn: "15m"})

    sessionTokens.push(sessionToken)
    return sessionToken
}



module.exports=generateSessionToken