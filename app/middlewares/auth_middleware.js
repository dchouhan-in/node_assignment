const jwt = require("jsonwebtoken");
const mongoose = require('mongoose')
const fs = require('fs');
const path = require('path');
const { HttpStatusCode } = require("axios");
const validatePassword = require("../utils/common");
const config = process.env


const UserSchema = new mongoose.Schema({
    mail: String,
    password: String,
    salt: String,
    counter: Number
});


let publicKey
fs.readFile(path.resolve(__dirname, "../secrets/secret.key.pub"), 'utf-8', (err, data) => {
    publicKey = data
})

const User = mongoose.model('User', UserSchema);

mongoose.connect(config.MONGO_URL, { user: config.MONGO_USER, pass: config.MONGO_PASS })

const authorize = (req, res, next) => {
    const token =
        req.headers["authorization"];

    if (!token) {
        return res.status(403).send("provide token!");
    }

    verifyJwt(token, res, next)
    return next();
};

function verifyJwt(token, res, next) {
    jwt.verify(token, publicKey, function (err, decoded) {
        if (err) {
            return res.status(401).send("Invalid Token");
        }
        const { mail, password } = decoded

        if (!(mail && password)) {
            return res.status(HttpStatusCode.BadRequest).send("provide email and password");
        }

        verifyPassword(mail, decoded, res, next)

        console.log(decoded);

    });

}

function verifyPassword(mail, decoded, res, next) {

    User.findOne({ mail }).then((user) => {
        if (!user) {
            return res.status(HttpStatusCode.Unauthorized).send("username unmatched!");
        }

        validatePassword(decoded.password, user).then((isPassValid) => {
            if (isPassValid) {
                res.local
                return next();
            }
            return res.status(HttpStatusCode.Unauthorized).send("invalid password!");


        }, (reason) => {
            return res.status(HttpStatusCode.InternalServerError).send("error!");
        })


    }, () => {

        return res.status(HttpStatusCode.InternalServerError).send("error!");

    })
}

module.exports = { authorize, UserSchema };