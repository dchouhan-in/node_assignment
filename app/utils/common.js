const bcrypt = require('bcrypt')

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

module.exports = validatePassword