const Joi = require('joi');


const signupSchema = Joi.object({
    email: Joi.string()
        .min(6)
        .max(60)
        .required()
        .email({ tlds: { allow: ['com', 'net'] } }),
    password: Joi.string()
        .required()
        .pattern(new RegExp('^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{6,}$'))
        .messages({
            'string.pattern.base': 'Password must be at least 6 characters long and include an uppercase letter, a lowercase letter, a number, and a special character.',
        }),
    fullname: Joi.string().required(),
    phone: Joi.string().required().pattern(new RegExp('^[0-9]{10}$')),
});


const signinSchema = Joi.object({
    email: Joi.string()
        .min(6)
        .max(60)
        .required()
        .email({ tlds: { allow: ['com', 'net'] } }),
        password: Joi.string()
        .required()
        .pattern(new RegExp('^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{6,}$'))
        .messages({
            'string.pattern.base': 'Password must be at least 6 characters long and include an uppercase letter, a lowercase letter, a number, and a special character.',
        }),
    })

const acceptCodeSchema = Joi.object({
    email: Joi.string()
        .min(6)
        .max(60)
        .required()
        .email({ tlds: { allow: ['com', 'net'] } }),
    providedCode: Joi.number().required(),
});

const changePasswordSchema = Joi.object({
    oldPassword: Joi.string()
        .required()
        .pattern(new RegExp('^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,}$'))
        .messages({
            'string.pattern.base': 'Password must be at least 8 characters long and include an uppercase letter, a lowercase letter, a number, and a special character.',
        }),
    newPassword: Joi.string()
        .required()
        .pattern(new RegExp('^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,}$'))
        .messages({
            'string.pattern.base': 'Password must be at least 8 characters long and include an uppercase letter, a lowercase letter, a number, and a special character.',
        }),
});

const acceptFPCodeSchema = Joi.object({
    email: Joi.string()
        .min(6)
        .max(60)
        .required()
        .email({ tlds: { allow: ['com', 'net'] } }),
    providedCode: Joi.number().required(),
    newPassword: Joi.string()
        .required()
        .pattern(new RegExp('^(?=.*[a-z])(?=.*[A-Z])(?=.*d).{8,}$')),
});

const createPostSchema = Joi.object({
    title: Joi.string().min(3).max(60).required(),
    description: Joi.string().min(3).max(600).required(),
    userId: Joi.string().required(),
});

module.exports = {
    signupSchema,
    signinSchema,
    acceptCodeSchema,
    changePasswordSchema,
    acceptFPCodeSchema,
    createPostSchema,
};
