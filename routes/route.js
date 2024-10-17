const express = require('express');
const router = express.Router();

const authC = require('../controller/auth');



router.post('/register',authC.register);

router.post('/login', authC.login);



router.post('/forgot-password', authC.forgotPassword);

router.post('/reset-password', authC.resetPassword);

//router.post('/verify-email', authC.verifyEmail);

router.post('/verify-email', authC.sendOtpForVerification);

router.post('/verify', authC.verifyOtp);



module.exports = router;
