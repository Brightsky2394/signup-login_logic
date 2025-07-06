const express = require('express');
const { signup, login, makeAdmin, forgotPassword, verifyOtp, resetPassword } = require('../controller/user.controller');
const router = express.Router();

router.post('/signup', signup);
router.post('/login', login);
router.patch('/admin/:userId', makeAdmin);
router.post('/forgot-password', forgotPassword);
router.post('/verify-otp', verifyOtp);
router.post('/reset-password/:userId', resetPassword);
module.exports = router;