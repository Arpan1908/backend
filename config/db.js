require('dotenv').config()
const mongoose = require('mongoose');

const connect = async () => {
    try {
        await mongoose.connect(process.env.MONGO_URI);
        console.log('Database connection established');
    } catch (err) {
        console.error(err.message);
        process.exit(1);
    }
};

module.exports = connect;