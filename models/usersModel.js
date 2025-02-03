const mongoose = require('mongoose');

const userSchema = mongoose.Schema(
    {
        email: {
            type: String,
            required: [true, 'Email is required!'],
            trim: true,
            unique: [true, 'Email must be unique!'],
            minLength: [5, 'Email must have at least 5 characters!'],
            lowercase: true,
        },
        password: {
            type: String,
            required: [true, 'Password must be provided!'],
            trim: true,
            select: false,
        },
        verified: {
            type: Boolean,
            default: false,
        },
        verificationCode: {
            type: String,
            select: false, // Exclude from queries by default
        },
        verificationCodeValidation: {
            type: Number,
            select: false, // Exclude from queries by default
        },
        forgotPasswordCode: {
            type: String,
            select: false,
        },
        forgotPasswordCodeValidation: {
            type: Number,
            select: false,
        },
        fullname: {
            type: String,
            required: [true, 'Full name is required!'],
            trim: true,
            minLength: [3, 'Full name must have at least 3 characters!'],
        },
        phone: {
            type: String,
            required: [true, 'Phone number is required!'],
            trim: true,
            unique: [true, 'Phone number must be unique!'],
            match: [/^\+?[1-9]\d{1,14}$/, 'Phone number must be valid!'], // Validates E.164 format
        },
        bikenames: {
            type: String,
           trim: true,
        },
        address: {
            type: String,
            trim: true,
        },
        about: {
            type: String,
            trim: true,
        },
        image: {
            type: String,
			default: '',
        },
    },
    {
        timestamps: true,
    }
);

module.exports = mongoose.model('User', userSchema);
