require('dotenv').config();
const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.MY_GMAIL,
        pass: process.env.MY_GMAIL_PASS
    }
})

module.exports = transporter;
