const User = require('../models/User');
const Token = require('../models/Token');
const jwt = require('jsonwebtoken');
const { generateAccessToken, generateRefreshToken } = require('../utils/generateToken');
const sendEmail = require('../services/email.service');
const crypto = require('crypto');
const logger = require('../utils/logger');

// ================= REGISTER =================
exports.register = async (req, res) => {
  const { name, email, password } = req.body;

  try {
    let user = await User.findOne({ email });
    if (user) {
      return res.status(400).json({ success: false, message: 'User already exists' });
    }

    user = new User({ name, email, password });
    await user.save();

    const verifyToken = crypto.randomBytes(32).toString('hex');
    user.resetPasswordToken = verifyToken;
    user.resetPasswordExpires = Date.now() + 3600000;
    await user.save();

    const verificationUrl = `${process.env.BASE_URL}/api/auth/verify-email/${verifyToken}`;
    await sendEmail({
      to: user.email,
      subject: 'Verify Your Email',
      html: `<p>Please verify your email:</p><a href="${verificationUrl}">Verify Email</a>`,
    });

    res.status(201).json({
      success: true,
      message: 'User registered. Please check your email to verify your account.',
    });
  } catch (err) {
    logger.error('Register error:', err.message);
    res.status(500).json({ success: false, message: 'Server error' });
  }
};

// ================= VERIFY EMAIL =================
exports.verifyEmail = async (req, res) => {
  try {
    const user = await User.findOne({
      resetPasswordToken: req.params.token,
      resetPasswordExpires: { $gt: Date.now() },
    });

    if (!user) {
      return res.status(400).json({ success: false, message: 'Invalid or expired token' });
    }

    user.isVerified = true;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();

    res.json({ success: true, message: 'Email verified successfully!' });
  } catch (err) {
    logger.error('Verify email error:', err.message);
    res.status(500).json({ success: false, message: 'Server error' });
  }
};

// ================= LOGIN =================
exports.login = async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user || !(await user.matchPassword(password))) {
      return res.status(400).json({ success: false, message: 'Invalid credentials' });
    }

    if (!user.isVerified) {
      return res.status(401).json({ success: false, message: 'Please verify your email first' });
    }

    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);

    await Token.create({
      userId: user._id,
      token: refreshToken,
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    });

    res.json({
      success: true,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
      accessToken,
      refreshToken,
    });
  } catch (err) {
    logger.error('Login error:', err.message);
    res.status(500).json({ success: false, message: 'Server error' });
  }
};

// ================= FORGOT PASSWORD =================
exports.forgotPassword = async (req, res) => {
  try {
    const user = await User.findOne({ email: req.body.email });
    if (!user) {
      return res.json({ success: true, message: 'If email exists, a reset link was sent.' });
    }

    const token = crypto.randomBytes(32).toString('hex');
    user.resetPasswordToken = token;
    user.resetPasswordExpires = Date.now() + 3600000;
    await user.save();

    const resetUrl = `${process.env.BASE_URL}/api/auth/reset-password/${token}`;
    await sendEmail({
      to: user.email,
      subject: 'Password Reset',
      html: `<p>Reset password:</p><a href="${resetUrl}">Reset Password</a>`,
    });

    res.json({ success: true, message: 'Password reset link sent.' });
  } catch (err) {
    logger.error('Forgot password error:', err.message);
    res.status(500).json({ success: false, message: 'Server error' });
  }
};

// ================= RESET PASSWORD =================
exports.resetPassword = async (req, res) => {
  try {
    const user = await User.findOne({
      resetPasswordToken: req.params.token,
      resetPasswordExpires: { $gt: Date.now() },
    });

    if (!user) {
      return res.status(400).json({ success: false, message: 'Invalid or expired token' });
    }

    user.password = req.body.newPassword;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();

    res.json({ success: true, message: 'Password updated successfully' });
  } catch (err) {
    logger.error('Reset password error:', err.message);
    res.status(500).json({ success: false, message: 'Server error' });
  }
};

// ================= REFRESH TOKEN =================
exports.refreshToken = async (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) {
    return res.status(401).json({ success: false, message: 'Refresh token required' });
  }

  try {
    const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);

    const tokenRecord = await Token.findOne({
      token: refreshToken,
      userId: decoded.userId,
      blacklisted: false,
      expiresAt: { $gt: new Date() },
    });

    if (!tokenRecord) {
      return res.status(403).json({ success: false, message: 'Invalid or expired refresh token' });
    }

    const user = await User.findById(decoded.userId);
    const newAccessToken = generateAccessToken(user);

    res.json({ success: true, accessToken: newAccessToken });
  } catch {
    res.status(403).json({ success: false, message: 'Invalid refresh token' });
  }
};

// ================= LOGOUT (NO REDIS) =================
exports.logout = async (req, res) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(400).json({
        success: false,
        message: 'Refresh token required',
      });
    }

    await Token.findOneAndUpdate(
      { token: refreshToken },
      { blacklisted: true }
    );

    res.json({
      success: true,
      message: 'Logged out successfully',
    });
  } catch (err) {
    logger.error('Logout error:', err.message);
    res.status(500).json({ success: false, message: 'Server error' });
  }
};
