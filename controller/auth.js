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
      // Find the user by email
      const user = await User.findOne({ email });
      if (!user) return res.status(400).json({ message: 'Email is not verified. Please verify your email first.' });
  
      // Check if the email is verified
      if (!user.verified) {
        return res.status(400).json({ message: 'Please verify your email before registering.' });
      }
  
      // Hash the password
      const hashedPassword = await bcrypt.hash(password, 10);
  
      // Update the user's details
      user.firstName = firstName;
      user.lastName = lastName;
      user.password = hashedPassword;
      await user.save();
  
      res.status(201).json({ message: 'Registration successful' });
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
      if (user.otp !== otp || user.expiry < Date.now()) {
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



  const sendOtpForVerification = async (req, res) => {
    const { email } = req.body;
  
    try {
      // Check if user already exists
      const user = await User.findOne({ email });
      if (user) {
        return res.status(400).json({ message: 'Email is already registered' });
      }
  
      // Generate OTP and expiration time
      const otp = generateOTP();
      const otpExpires = Date.now() + 5 * 60 * 1000; // OTP valid for 5 minutes
  
      // Create temporary user record with OTP (not verified yet)
      const newUser = new User({
        email,
        otp,
        otpExpires,
        verified: false, // Not verified yet
      });
  
      // Save the user with OTP
      await newUser.save();
  
      // Send OTP to the user's email
      await transport.sendMail({
        to: email,
        subject: 'Email Verification OTP',
        html: `<h2>Email Verification</h2>
               <p>Your OTP is: <b>${otp}</b>. It is valid for 5 minutes.</p>`,
      });
  
      res.status(200).json({ message: 'OTP sent to email' });
    } catch (error) {
      res.status(500).json({ message: 'Server error', error });
    }
  };
  
  // Verify OTP and Mark Email as Verified
  const verifyOtp = async (req, res) => {
    const { email, otp } = req.body;
  
    try {
      // Find the user by email
      const user = await User.findOne({ email });
      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }
  
      // Check if OTP is correct and not expired
      if (user.otp !== otp || user.expiry < Date.now()) {
        return res.status(400).json({ message: 'Invalid or expired OTP' });
      }
  
      // Mark the user as verified
      user.verified = true;
      user.otp = undefined; // Clear OTP
      user.expiry = undefined; // Clear OTP expiration
      await user.save();
  
      res.status(200).json({ message: 'Email verified successfully' });
    } catch (error) {
      res.status(500).json({ message: 'Server error', error });
    }
  };
  

module.exports = {
  register,
  login,
  forgotPassword,
  resetPassword,
  verifyEmail,
  sendOtpForVerification,
  verifyOtp
};

