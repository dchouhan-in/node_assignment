const express = require('express')

const mongoose = require('mongoose')


const MONGO_HOST = process.env.MONGO_HOST


mongoose.connect('mongodb://127.0.0.1:27017/myapp');


const app = express()
const port = 3000

app.post('/register', (req, res) => {
    
})

app.listen(port, () => {
    console.log(`listening on port ${port}`)
})