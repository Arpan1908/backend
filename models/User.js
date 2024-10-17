const mongoose = require('mongoose');

const Schema = new mongoose.Schema({
    firstName:{
        required: true,
        type: 'string'
    },
    lastName:{
        required: true,
        type:'string'
    },
    email:{
        required: true,
        type:'string',
        unique: true,
        
    },
    password:{
        required: true,
        type:'string',
        minlength: 8
    },
    verified:{
        default: false,
        type: 'boolean'
    },
    otp:{
        type:'string',
        
    },
    expiry:{
        type: Date,
        
    }

});

module.exports = mongoose.model('User', Schema);