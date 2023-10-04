const express = require('express')

const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
var jwt = require('jsonwebtoken');
const { HttpStatusCode } = require('axios');

const { authorize } = require('./middlewares/auth_middleware')
var bodyParser = require('body-parser')

const asyncHandler = require("express-async-handler");

const validatePassword = require("./utils/common");

var jsonParser = bodyParser.json()

const config = process.env



const fs = require('fs');

const path = require('path');
fs.readFile(path.resolve(__dirname, "./secrets/secret.key"), 'utf-8', (err, data) => {
    privateKey = data.trim()
})


mongoose.connect(config.MONGO_URL, { user: config.MONGO_USER, pass: config.MONGO_PASS })

const User = mongoose.models.User

const app = express()
app.use(jsonParser)
const port = 3000

app.post('/register', asyncHandler(async (req, res) => {

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




function signToken(mail, password) {
    var payload = { mail, password }

    var token = jwt.sign(payload, privateKey, { algorithm: 'RS256', expiresIn: '1d' });

    return token
}


async function createUser(mail, password) {

    bcrypt.genSalt(10, function (err, salt) {
        bcrypt.hash(password, salt, (err, hash) => {
            return User.create({ mail, password: hash, salt, counter: 0 })
        });
    });
}

app.get('/counter', authorize, asyncHandler(async (req, res) => {
    let mail = res.locals.mail
    let count_incr = res.locals.counter + 1


    if (mail) {
        try {
            user = await User.findOneAndUpdate({ mail }, { counter: count_incr })

        } catch (error) {

            return res.status(HttpStatusCode.InternalServerError).send("error!");

        }
    }


    return res.status(HttpStatusCode.Ok).send({ count: count_incr });
}))

app.post('/reset', authorize, asyncHandler(async (req, res) => {
    console.log(req.body);


    let resetTo = req.body.count

    let mail = res.locals.mail

    if (mail) {
        await User.findOneAndUpdate({ mail }, { counter: resetTo })
    }

    return res.status(HttpStatusCode.Ok).send({ count: resetTo });

}))

app.listen(port, () => {
    console.log(`listening on port ${port}`)
})
