const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const transport = require('../config/mailer');
const User = require('../models/User');
require('dotenv').config();
const crypto = require('crypto');

const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRES_IN = '5min';

// Generate OTP
const generateOTP = () => {
  const otp = crypto.randomBytes(3).toString('hex'); 
  return otp.toUpperCase();
};


const register = async (req, res) => {
  const { firstName, lastName, email, password } = req.body;

  try {
    // Check if user already exists
    const userExists = await User.findOne({ email });
    if (userExists) return res.status(400).json({ message: 'User already exists' });

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Generate OTP for email verification
    const otp = generateOTP();
    const otpExpires = Date.now() + 5 * 60 * 1000; // OTP valid for 5 minutes

    // Create a new user but don't save it until OTP is verified
    const newUser = new User({
      firstName,
      lastName,
      email,
      password: hashedPassword,
      verified: false, // Mark user as not verified
      otp,
      otpExpires
    });

    // Send OTP email
    await transport.sendMail({
      to: email,
      subject: 'Verify your email',
      html: `<h2>Email Verification</h2>
             <p>Your OTP is: <b>${otp}</b>. It is valid for 5 minutes.</p>`,
    });

    // Save user with OTP (without marking as verified)
    await newUser.save();

    res.status(200).json({ message: 'OTP sent to your email for verification' });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error });
  }
};


const verifyEmail = async (req, res) => {
  const { email, otp } = req.body;

  try {
    // Find the user
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: 'User not found' });

    // Check if OTP is valid
    if (user.otp !== otp || user.expiry < Date.now()) {
      return res.status(400).json({ message: 'Invalid or expired OTP' });
    }

    // Mark user as verified
    user.verified = true;
    user.otp = undefined; // Clear OTP
    user.expiry = undefined; // Clear OTP expiration time
    await user.save();

    // Generate JWT token
    const token = jwt.sign({ id: user._id, email: user.email }, JWT_SECRET, {
      expiresIn: JWT_EXPIRES_IN,
    });

    res.status(200).json({
      message: 'Email verified successfully, registration complete',
      token,
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error });
  }
};


const login = async (req, res) => {
  const { email, password } = req.body;

  try {
    // Find the user by email
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: 'Invalid credentials' });

    // Check if the user is verified
    if (!user.verified) {
      return res.status(403).json({ message: 'Please verify your email before logging in' });
    }

    // Compare passwords
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });

    // Generate JWT token
    const token = jwt.sign({ id: user._id, email: user.email }, JWT_SECRET, {
      expiresIn: JWT_EXPIRES_IN,
    });

    res.status(200).json({
      message: 'Login successful',
      token,
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error });
  }
}
  

  const forgotPassword = async (req, res) => {
    const { email } = req.body;
  
    try {
      // Check if user exists
      const user = await User.findOne({ email });
      if (!user) return res.status(404).json({ message: 'User not found' });
  
      // Generate OTP
      const otp = generateOTP();
      const otpExpires = Date.now() + 5 * 60 * 1000; 
      // Store the OTP and expiration time in the user's record
      user.otp = otp;
      user.expiry = otpExpires;
      await user.save();
  
      // Send OTP email
      await transport.sendMail({
        to: user.email,
        subject: 'Password Reset OTP',
        html: `<h2>Password Reset Request</h2>
               <p>Your OTP is: <b>${otp}</b>. It is valid for 5 min.</p>`,
      });
  
      res.status(200).json({ message: 'OTP sent to your email' });
    } catch (error) {
      res.status(500).json({ message: 'Server error', error });
    }
  };


const resetPassword = async (req, res) => {
    const { email, otp, password } = req.body;
  
    try {
      // Find the user by email
      const user = await User.findOne({ email });
      if (!user) return res.status(404).json({ message: 'User not found' });
  
      // Check if OTP is valid
      if (user.resetPasswordOtp !== otp || user.expiry < Date.now()) {
        return res.status(400).json({ message: 'Invalid or expired OTP' });
      }
  
      // Hash the new password
      const hashedPassword = await bcrypt.hash(password, 10);
  
      // Update the user's password
      user.password = hashedPassword;
      user.otp = undefined; // Clear the OTP
      user.expiry = undefined; // Clear OTP expiration time
      await user.save();
  
      res.status(200).json({ message: 'Password reset successful' });
    } catch (error) {
      res.status(500).json({ message: 'Server error', error });
    }
  };
  

module.exports = {
  register,
  login,
  forgotPassword,
  resetPassword,
  verifyEmail
};

