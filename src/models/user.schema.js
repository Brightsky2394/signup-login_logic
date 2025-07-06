const mongoose = require('mongoose');


const userSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
        trim: true
    },
    email: {
        type: String,
        required: true,
        unique: true,
        trim: true
    },
    password: {
        type: String,
        required: true,
        trim: true,
        minlength: 6
    },
    isAdmin: {
        type: Boolean,
        default: false
    },
    otp: String,
    otpVerified: {
        type: Boolean,
        default: false
    }
},
{
    timestamps: true,
    versionKey: false
}
);

module.exports = mongoose.model('User', userSchema);