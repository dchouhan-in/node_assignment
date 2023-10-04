const jwt = require("jsonwebtoken");
const { privateKey } = require("../main");

const authorize = (req, res, next) => {
    const token =
        req.headers["Authorization"];

    if (!token) {
        return res.status(403).send("provide token!");
    }
    try {
        const decoded = jwt.verify(token, privateKey);
        console.log(decoded);
    } catch (err) {
        return res.status(401).send("Invalid Token");
    }
    return next();
};

module.exports = authorize;