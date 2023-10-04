const express = require('express')

const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
var jwt = require('jsonwebtoken');
const { HttpStatusCode } = require('axios');

var bodyParser = require('body-parser')

const asyncHandler = require("express-async-handler");


var jsonParser = bodyParser.json()


const MONGO_HOST = process.env.MONGO_HOST
const MONGO_PASS = process.env.MONGO_PASS
const MONGO_USER = process.env.MONGO_USER
const MONGO_PORT = process.env.MONGO_PORT
const MONGO_DB = process.env.MONGO_DB

const MONGO_URL = `mongodb://${MONGO_USER}:${MONGO_PASS}@${MONGO_HOST}:${MONGO_PORT}/${MONGO_DB}?authSource=admin`
const privateKey = String.raw`-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDJp+h7I1/FL83F
4dRpVKRW0g1fqdPJovu5BcM0pkVtT5eDWZ+WBzhVSU5qii/QIQ0vw8LU51k+DLbV
wKS83qZnyS865Qar5rcrsnWY+pqaA9/ka4H5la5cEb0nGzLb8opdKMByamuC/0fo
sXCqhSu/QQ9PJHpo3S5U6q3RrtKAxoGTzVtMLVfWVkNicRdGBnRZuwLRSjZu/Bg9
kI/QANVZXDs2D7e9enqz2FLwBzFbgZdFX6hpeW9lzcGLv5wmKNM6BLpl9OYYqcr1
ViOOMB56uCUj4h1rc8KjVPhbDk2XYJ4aipO+LlyzPUO0CXXa/fFMOVupQTjQGWyt
R2uXWbBXAgMBAAECggEABtU7rsB6GZ0PDz93Cm1QduiohK9Pz9XyoEhZCaBWBegx
LXA3VMbAhT31/EIxGzpOJL+GCzTI9K31nAnqYG6i8NgDqQPi//wnWhcH87u6IAc1
lPCCTPS3cxiJckPHq2WX2U7s28j4r6L6yssIaElu5rd2T1Y1wkvhqrBGXNkxpM9a
923fylUl6+wdSY+Q18QHBP4QxICXtqaDnr9oop8tKLqmw4Hh8SoS+kKz+JHnYzm6
Z3l7GxLJGnsciRlujCEzNM8LEq+ikRSrHJ/bIft0wAzVC043jfpBrkGknXdfVven
+Yf7ORdDUpPqKTSa6DWabZvf7lXyQsJ0Jhqr7CFTIQKBgQD+H3xmIu6IrQs9bgbO
U63c/8GHEULWZtPpignt7s/docCcn+drjnOd57Ihqg5NfhAxP/vWCW0cJm6GqihS
charF1YmnTeWrl3R7XDRm2iGt4CrBrMsbED8Cxwv0iB9/ad8huIE0ST1Ux95qelx
t9pB9a1ChTeT19Qn3O+STtkn+QKBgQDLJTav0K2uEU9+usDaRwP2JfkgdY3r1t4Q
bdrIEo2aCxfL/STTZw0l7HbwampUyWjBuQKwQ9r29C8n82zAao0LstS13JAhJMFi
GDsd795B0fGk+4ebvlsCez/A4BUk3ngobwEVcz6J+l99q+QOpjFx8iQrBgCBxCh/
Y5PKqljOzwKBgQDRSXEUVPSKj6lQIEtupa/s8J2b9XVMSkeAcPUYhbOf3lVZKMBY
7mr9wxILc5hv7cC8LuvjLMQ1iNlCAuVOcTOGGKQVDSn46QXPnHNrzUfam0pWkCAE
F+u1KBlAsReda8gCYLvIJ87+VET52BuwUjBoXkMhI8HP+tJ5OhX8Mv/ZUQKBgGYI
cfhKswFr9marvHOmGapHlmKkSL089dqAotO85dyKV9CAfD+mUedLZs4IVRHy+6fZ
mi0YV+GT8h9515Spr+BBWS9i8g2DnZH8o6y8rwCWR23bXFhwetu7NeFVa6lSCD4e
yweQE8hPtiiz7l8hQFKAEYR+hkCnWsPpKvEvMF3nAoGAS2z95uGdr5jSnWdg/wFU
36zol2SxRg20zf/vMWHF15uATCZhI6DzX93x5BeBx4qzIr0dv1QC4rFUvVYRCgPN
n7ANnomVKbWGCfF5GXHwuQjLO2iXlb5T9hqN0qE55G9lX9acGeuPTgepgwlhIaql
tmCXtQi20D7k2gx8wG6hWdE=
-----END PRIVATE KEY-----
`


const UserSchema = new mongoose.Schema({
    mail: String,
    password: String,
    salt: String,
});

const User = mongoose.model('User', UserSchema);
mongoose.connect(MONGO_URL, { user: MONGO_USER, pass: MONGO_PASS })

const app = express()
const port = 3000

app.post('/register', jsonParser, asyncHandler(async (req, res) => {

    const { mail, password } = req.body

    if (!mail) {
        return res.status(400).send("please provide username empty!")
    }
    if (!password) {
        return res.status(400).send("please provide password empty!")
    }

    const user = await User.findOne({ mail })


    if (!user) {
        try {
            await createUser(mail, password)
            let token = signToken(mail, password)
            return res.status(HttpStatusCode.Created).send(token)
        } catch (error) {
            return res.status(HttpStatusCode.InternalServerError).send()
        }
    }

    if (mail != user.mail) {
        return res.status(HttpStatusCode.NotFound).send("mail not found!")
    }

    const isPassValid = await validatePassword(password, user)
    if (isPassValid) {
        let token = signToken(mail, password)
        return res.status(HttpStatusCode.Ok).send(token)
    } else {
        return res.status(HttpStatusCode.NotFound).send("invalid pass!")
    }

}))



function validatePassword(req_password, user) {
    const { password, salt } = user;
    return new Promise((resolve, reject) => {
        try {
            let isValid = bcrypt.compare(req_password, password)
            resolve(isValid)

        } catch (error) {
            reject(error)
        }
    })

}

function signToken(mail, password) {
    var payload = { mail, password }

    var token = jwt.sign(payload, privateKey, { algorithm: 'RS256', expiresIn: '1d' });
    return token
}


async function createUser(mail, password) {

    bcrypt.genSalt(10, function (err, salt) {
        bcrypt.hash(password, salt, (err, hash) => {
            return User.create({ mail, password: hash, salt })
        });
    });
}

app.listen(port, () => {
    console.log(`listening on port ${port}`)
})