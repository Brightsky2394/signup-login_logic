const User = require('../models/user.schema');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const saltRound = 10

const signup = async (req, res) => {
    const { name, email, password } = req.body;
    // validate inputs
    if ( !name || !email || !password ) {
        return res.status(400).json({
            message: "All fields are required"
        })
    };

    if ( password.length < 6 ) {
        return res.status(400).json({
            message: "Password must be of at least 6 characters"
        })
    };
    try {
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({
                message: "User already exist"
            })
        }
        const hashedPassword = await bcrypt.hash(password, saltRound);
        const newUser = new User({ name, email, password: hashedPassword });
        await newUser.save();
        return res.status(201).json({
            message: "User created successfully",
            newUser
        })
    } catch (err) {
        console.error('Error in creating user\n', err.message);
        return res.status(500).json({
            message: "Internal server error"
        })
    }
};

const login = async (req, res) => {
    const { email, password } = req.body;
    // validate inputs
    if (!email || !password) {
        return res.status(400).json({
            message: "Email and password is required"
        })
    }
    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({
                message: "User not found"
            })
        }
        // validate password
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({
                message: "Unauthorize user"
            })
        }
        const token = await jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRATION });
        return res.status(200).json({
            message: "User successfully login",
            user,
            token
        })
    } catch (err) {
        console.error("Error in logging in user\n", err.message);
        return res.status(500).json({
            message: "Internal server error"
        })
    }
};

const makeAdmin = async (req, res) => {
    const { userId } = req.params;
    if (!userId) {
        return res.status(400).json({
            message: "User ID is required"
        })
    }
    try {
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({
                message: "User not found"
            })
        }
        user.isAdmin = true;
        await user.save();
        return res.status(200).json({
            message: "User promoted to Admin successfully",
            user
        })
    } catch (err) {
        console.error("Error in creating Admin\n", err.message);
        return res.status(500).json({
            message: "Internal server error"
        })
    }
};

const forgotPassword = async (req, res) => {
    const { email } = req.body;
    // validate input
    if (!email) {
        return res.status(400).json({
            message: "Email field is required"
        })
    }
    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({
                message: "User not found"
            })
        }
        const otp = Math.floor( 100000 + Math.random() * 900000 ).toString();
        user.otp = otp;
        await user.save();
        return res.status(200).json({
            message: "Reset token created successfully",
            user
        })
    } catch (err) {
        console.error('Error creating reset token\n', err.message);
        return res.status(500).json({
            message: "Internal server error"
        })
    }
};

const verifyOtp = async (req, res) => {
    const { otp } = req.body;
    // validate input
    if (!otp) {
        return res.status(400).json({
            message: "OTP is required"
        })
    }
    try {
        const user = await User.findOne({ otp });
        if (!user) {
            return res.status(404).json({
                message: "User not found"
            })
        }
        
        user.otpVerified = true;
        user.otp = null;
        await user.save();
        return res.status(200).json({
            message: "OTP verified successfully",
            _id: user._id
        })
    } catch (err) {
        console.error("Error in verifying OTP\n", err.message);
        return res.status(500).json({
            message: "Internal server error"
        })
    }
};

const resetPassword = async (req, res) => {
    const { newPassword, confirmPassword } = req.body;
    const { userId } = req.params;
    // validate inputs
    if (!newPassword || !userId) {
        return res.status(400).json({
            message: "New Password and User ID is required"
        })
    }
    // validate password
    if (newPassword !== confirmPassword) {
        return res.status(400).json({
            message: "Passwords do not match"
        })
    }
    try {
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({
                message: "User not found"
            })
        }
        if (user.otpVerified === false) {
            return res.status(403).json({
                message: "OTP not verified, please verify OTP"
            })
        }
        const hashedPassword = await bcrypt.hash(newPassword, saltRound);
        user.password = hashedPassword;
        user.otpVerified = false;
        await user.save();
        return res.status(200).json({
            message: "User password successfully reset"
        })
    } catch (err) {
        console.error("Error in resetting password\n", err.message);
        return res.status(500).json({
            message: "Internal server error"
        })
    }
};

module.exports = { signup, login, makeAdmin, forgotPassword, verifyOtp, resetPassword }