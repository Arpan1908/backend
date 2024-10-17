const mongoose = require('mongoose');

const Schema = new mongoose.Schema({
    firstName:{
        
        type: 'string'
    },
    lastName:{
        
        type:'string'
    },
    email:{
        required: true,
        type:'string',
        unique: true,
        
    },
    password:{
        
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
