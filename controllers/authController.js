const jwt = require('jsonwebtoken');
const {
	
	signinSchema,
	acceptCodeSchema,
	changePasswordSchema,
	acceptFPCodeSchema,
} = require('../middlewares/validator');
 const {signupSchema}  = require('../middlewares/validator')
const User = require('../models/usersModel');
const { doHash, doHashValidation, hmacProcess } = require('../utils/hashing');
const transport = require('../middlewares/sendMail');


const crypto = require('crypto');
const nodemailer = require('nodemailer');


const authenticate = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) {
        return res.status(403).json({ success: false, message: 'Token is missing' });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).json({ success: false, message: 'Invalid or expired token' });
        }
        req.user = decoded; // Attach the decoded user data to the request
        next();
    });
};





const signup = async (req, res) => {

    const { email, password, fullname, phone } = req.body;

    try {
        const { error } = signupSchema.validate({ email, password, fullname, phone });

        if (error) {
            console.log('Validation Error:', error.details[0].message);
            return res.status(401).json({
                success: false,
                message: error.details[0].message,
            });
        }

        const existingUser = await User.findOne({
            $or: [{ email }, { phone }],
        });

        if (existingUser) {
            console.log('User already exists with email or phone:', existingUser);
            return res.status(401).json({
                success: false,
                message: 'User with this email or phone already exists!',
            });
        }

        const hashedPassword = await doHash(password, 12);

        // Generate OTP
        const otp = crypto.randomInt(100000, 999999); // Generate a 6-digit OTP
        const otpExpiration = Date.now() + 60 * 60 * 1000; // OTP valid for 60 minutes

        // Create a new user object
        const newUser = new User({
            email,
            password: hashedPassword,
            fullname,
            phone,
            verificationCode: otp,
            verificationCodeValidation: otpExpiration,
        });

        const result = await newUser.save();

        // Send OTP to the user's email
        const transporter = nodemailer.createTransport({
            service: 'Gmail',
            auth: {
                user: process.env.NODE_CODE_SENDING_EMAIL_ADDRESS, // Your email
                pass: process.env.NODE_CODE_SENDING_EMAIL_PASSWORD, // Your email password
            },
        });

        await transporter.sendMail({
            from: process.env.EMAIL,
            to: email,
            subject: 'Your Verification Code',
            text: `Your OTP is ${otp}. It is valid for 60 minutes.`,
        });


        res.status(201).json({
            success: true,
            otp:otp,
            message: 'Your account has been created. Please verify your email with the OTP sent.',
        });
    } catch (error) {
        console.error('Error in signup:', error);
        res.status(500).json({
            success: false,
            message: 'An error occurred while creating your account. Please try again later.',
        });
    }
};

const verifyOtp = async (req, res) => {
    const { email, otp } = req.body;

    try {
        const user = await User.findOne({ email }).select('+verificationCode +verificationCodeValidation');

        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found!',
            });
        }

        if (user.verified) {
            return res.status(400).json({
                success: false,
                message: 'User is already verified!',
            });
        }

        if (user.verificationCode !== otp) {
            return res.status(400).json({
                success: false,
                message: 'Invalid OTP!',
            });
        }

        if (user.verificationCodeValidation < Date.now()) {
            return res.status(400).json({
                success: false,
                message: 'OTP has expired!',
            });
        }

        // Create JWT token
        const token = jwt.sign(
            {
                userId: user._id,
                email: user.email,
                verified: user.verified,
            },
            process.env.TOKEN_SECRET,
            { expiresIn: '8h' }
        );

        // Mark the user as verified
        user.verified = true;
        user.verificationCode = undefined;
        user.verificationCodeValidation = undefined;

        await user.save();

        res.status(200).json({
            success: true,
            token: token,
            message: 'Your account has been verified successfully!',
        });
    } catch (error) {
        console.error('Error in OTP verification:', error);
        res.status(500).json({
            success: false,
            message: 'An error occurred while verifying your account. Please try again later.',
        });
    }
};





  
const signin = async (req, res) => {
    try {
        const { email, password } = req.body;
        console.log('Extracted Email:', email, 'Extracted Password:', password);

        const { error } = signinSchema.validate({ email, password });
        if (error) {
            console.log('Validation Error:', error);
            return res.status(401).json({
                success: false,
                message: error.details[0].message,
            });
        }

        const existingUser = await User.findOne({ email }).select('+password');
        if (!existingUser) {
            return res.status(401).json({
                success: false,
                message: 'User does not exist!',
            });
        }

        const result = await doHashValidation(password, existingUser.password);
        if (!result) {
            return res.status(401).json({
                success: false,
                message: 'Invalid credentials!',
            });
        }

        const token = jwt.sign(
            {
                userId: existingUser._id,
                email: existingUser.email,
                verified: existingUser.verified,
            },
            process.env.TOKEN_SECRET,
            { expiresIn: '8h' }
        );

        res
            .cookie('Authorization', 'Bearer ' + token, {
                expires: new Date(Date.now() + 8 * 3600000),
                httpOnly: process.env.NODE_ENV === 'production',
                secure: process.env.NODE_ENV === 'production',
            })
            .json({
                success: true,
                token,
                message: 'Logged in successfully',
            });
    } catch (error) {
        console.error('Error in signin:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error',
        });
    }
};

  

exports.signout = async (req, res) => {
	res
		.clearCookie('Authorization')
		.status(200)
		.json({ success: true, message: 'logged out successfully' });
};

const sendVerificationCode = async (req, res) => {
	const { email } = req.body;
	try {
		const existingUser = await User.findOne({ email });
		if (!existingUser) {
			return res
				.status(404)
				.json({ success: false, message: 'User does not exists!' });
		}
		if (existingUser.verified) {
			return res
				.status(400)
				.json({ success: false, message: 'You are already verified!' });
		}

		const codeValue = Math.floor(Math.random() * 1000000).toString();
		let info = await transport.sendMail({
			from: process.env.NODE_CODE_SENDING_EMAIL_ADDRESS,
			to: existingUser.email,
			subject: 'verification code',
			html: '<h1>' + codeValue + '</h1>',
		});

		if (info.accepted[0] === existingUser.email) {
			const hashedCodeValue = hmacProcess(
				codeValue,
				process.env.HMAC_VERIFICATION_CODE_SECRET
			);
			existingUser.verificationCode = hashedCodeValue;
			existingUser.verificationCodeValidation = Date.now();
			await existingUser.save();
			return res.status(200).json({ success: true, message: 'Code sent!' });
		}
		res.status(400).json({ success: false, message: 'Code sent failed!' });
	} catch (error) {
		console.log(error);
	}
};

const verifyVerificationCode = async (req, res) => {
	const { email, providedCode } = req.body;
	try {
		const { error, value } = acceptCodeSchema.validate({ email, providedCode });
		if (error) {
			return res
				.status(401)
				.json({ success: false, message: error.details[0].message });
		}

		const codeValue = providedCode.toString();
		const existingUser = await User.findOne({ email }).select(
			'+verificationCode +verificationCodeValidation'
		);

		if (!existingUser) {
			return res
				.status(401)
				.json({ success: false, message: 'User does not exists!' });
		}
		if (existingUser.verified) {
			return res
				.status(400)
				.json({ success: false, message: 'you are already verified!' });
		}

		if (
			!existingUser.verificationCode ||
			!existingUser.verificationCodeValidation
		) {
			return res
				.status(400)
				.json({ success: false, message: 'something is wrong with the code!' });
		}

		if (Date.now() - existingUser.verificationCodeValidation > 5 * 60 * 1000) {
			return res
				.status(400)
				.json({ success: false, message: 'code has been expired!' });
		}

		const hashedCodeValue = hmacProcess(
			codeValue,
			process.env.HMAC_VERIFICATION_CODE_SECRET
		);

		if (hashedCodeValue === existingUser.verificationCode) {
			existingUser.verified = true;
			existingUser.verificationCode = undefined;
			existingUser.verificationCodeValidation = undefined;
			await existingUser.save();
			return res
				.status(200)
				.json({ success: true, message: 'your account has been verified!' });
		}
		return res
			.status(400)
			.json({ success: false, message: 'unexpected occured!!' });
	} catch (error) {
		console.log(error);
	}
};





const changePassword =  async (req, res) => {
    const { userId, verified } = req.user; // Extract from the decoded token
    const { oldPassword, newPassword } = req.body;

    try {
        console.log("User from token:", req.user); // Log the user object to check 'verified'

        // Validate passwords
        const { error, value } = changePasswordSchema.validate({ oldPassword, newPassword });
        if (error) {
            console.log("Validation Error:", error.details); // Log validation error
            return res.status(400).json({ success: false, message: error.details[0].message });
        }

        // Check if the user is verified
        if (!verified) {
            console.log("User not verified:", verified); // Log to check 'verified' field
            return res.status(403).json({ success: false, message: 'You are not a verified user!' });
        }

        // Find the user in the database
        const existingUser = await User.findOne({ _id: userId }).select('+password');
        if (!existingUser) {
            return res.status(404).json({ success: false, message: 'User does not exist!' });
        }

        // Validate old password
        const result = await doHashValidation(oldPassword, existingUser.password);
        if (!result) {
            return res.status(401).json({ success: false, message: 'Invalid credentials!' });
        }

        // Hash and update the new password
        const hashedPassword = await doHash(newPassword, 12);
        existingUser.password = hashedPassword;
        await existingUser.save();

        return res.status(200).json({ success: true, message: 'Password updated successfully!' });
    } catch (error) {
        console.error("Error:", error); // Log the full error for debugging
        return res.status(500).json({ success: false, message: error.message || 'An error occurred!' });
    }
};

const sendForgotPasswordCode = async (req, res) => {
	const { email } = req.body;
	try {
		const existingUser = await User.findOne({ email });
		if (!existingUser) {
			return res
				.status(404)
				.json({ success: false, message: 'User does not exists!' });
		}

		const codeValue = Math.floor(Math.random() * 1000000).toString();
		let info = await transport.sendMail({
			from: process.env.NODE_CODE_SENDING_EMAIL_ADDRESS,
			to: existingUser.email,
			subject: 'Forgot password code',
			html: '<h1>' + codeValue + '</h1>',
		});

		if (info.accepted[0] === existingUser.email) {
			const hashedCodeValue = hmacProcess(
				codeValue,
				process.env.HMAC_VERIFICATION_CODE_SECRET
			);
			existingUser.forgotPasswordCode = hashedCodeValue;
			existingUser.forgotPasswordCodeValidation = Date.now();
			await existingUser.save();
			return res.status(200).json({ success: true, message: 'Code sent!',codeValue });
		}
		res.status(400).json({ success: false, message: 'Code sent failed!' });
	} catch (error) {
		console.log(error);
	}
};

// const sendForgotPasswordCode = async (req, res) => {
//     const { email } = req.body;
//     try {
//         const existingUser = await User.findOne({ email });
//         if (!existingUser) {
//             return res.status(404).json({ success: false, message: 'User does not exist!' });
//         }

//         // Generate a secure OTP
//         const codeValue = crypto.randomInt(100000, 999999).toString();

//         // Send OTP via email
//         let info = await transport.sendMail({
//             from: process.env.NODE_CODE_SENDING_EMAIL_ADDRESS,
//             to: existingUser.email,
//             subject: 'Forgot Password Code',
//             html: `<h1>${codeValue}</h1>`,
//         });

//         if (info.accepted.includes(existingUser.email)) {
//             const hashedCodeValue = hmacProcess(codeValue, process.env.HMAC_VERIFICATION_CODE_SECRET);
//             existingUser.forgotPasswordCode = hashedCodeValue;
//             existingUser.forgotPasswordCodeValidation = Date.now();
//             await existingUser.save();

//             return res.status(200).json({ success: true, message: 'Code sent successfully!' });
//         }

//         res.status(500).json({ success: false, message: 'Failed to send code!' });
//     } catch (error) {
//         console.error(error);
//         res.status(500).json({ success: false, message: 'An error occurred!' });
//     }
// };

const verifyForgotPasswordCode = async (req, res) => {
    const { email, providedCode, newPassword } = req.body;

    try {
        // Validate input
        const { error } = acceptFPCodeSchema.validate({ email, providedCode, newPassword });
        if (error) {
            return res.status(400).json({ success: false, message: error.details[0].message });
        }

        // Find user with stored code
        const existingUser = await User.findOne({ email }).select('+forgotPasswordCode +forgotPasswordCodeValidation');
        if (!existingUser) {
            return res.status(404).json({ success: false, message: 'User does not exist!' });
        }

        // Check if code exists
        if (!existingUser.forgotPasswordCode || !existingUser.forgotPasswordCodeValidation) {
            return res.status(400).json({ success: false, message: 'Invalid or missing code!' });
        }

        // Check if code is expired (5 minutes)
        if (Date.now() - existingUser.forgotPasswordCodeValidation > 5 * 60 * 1000) {
            return res.status(400).json({ success: false, message: 'Code has expired!' });
        }

        // Validate code
        const hashedCodeValue = hmacProcess(providedCode.toString(), process.env.HMAC_VERIFICATION_CODE_SECRET);
        if (hashedCodeValue !== existingUser.forgotPasswordCode) {
            return res.status(400).json({ success: false, message: 'Invalid code!' });
        }

        // Hash new password and update
        const hashedPassword = await doHash(newPassword, 12);
        existingUser.password = hashedPassword;
        existingUser.forgotPasswordCode = undefined;
        existingUser.forgotPasswordCodeValidation = undefined;
        await existingUser.save();

        return res.status(200).json({ success: true, message: 'Password updated successfully!' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ success: false, message: 'An error occurred!' });
    }
};


// exports.changePassword = async (req, res) => {
//     const { userId, verified } = req.user;
//     const { oldPassword, newPassword } = req.body;

//     try {
//         // Validate input
//         const { error } = changePasswordSchema.validate({ oldPassword, newPassword });
//         if (error) {
//             return res.status(400).json({ success: false, message: error.details[0].message });
//         }

//         if (!verified) {
//             return res.status(403).json({ success: false, message: 'User is not verified!' });
//         }

//         // Find user and check old password
//         const existingUser = await User.findOne({ _id: userId }).select('+password');
//         if (!existingUser) {
//             return res.status(404).json({ success: false, message: 'User does not exist!' });
//         }

//         const isPasswordValid = await doHashValidation(oldPassword, existingUser.password);
//         if (!isPasswordValid) {
//             return res.status(401).json({ success: false, message: 'Incorrect old password!' });
//         }

//         // Hash and update new password
//         const hashedPassword = await doHash(newPassword, 12);
//         existingUser.password = hashedPassword;
//         await existingUser.save();

//         return res.status(200).json({ success: true, message: 'Password updated successfully!' });
//     } catch (error) {
//         console.error(error);
//         return res.status(500).json({ success: false, message: 'An error occurred!' });
//     }
// };



const getProfile = async (req, res) => {
    try {
        // Ensure the user object is present in the request
        if (!req.user || !req.user.userId) {
            return res.status(401).json({
                success: false,
                message: 'Unauthorized access. User not authenticated.',
            });
        }

        // Extract the userId from the decoded token (attached by the authenticateUser middleware)
        const userId = req.user.userId;

        // Fetch the user from the database, excluding sensitive fields
        const user = await User.findById(userId).select('-password -verificationCode -verificationCodeValidation');

        // Check if the user was found
        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found!',
            });
        }

        // Construct the user profile response
        const userProfile = {
            _id: user._id,
            email: user.email,
            fullName: user.fullname,
            phone: user.phone,
            createdAt: user.createdAt,
            updatedAt: user.updatedAt,
        };

        // Return the user profile
        return res.status(200).json({
            success: true,
            user: userProfile,
        });
    } catch (error) {
        console.error('Error fetching user profile:', error.message);

        // Handle potential errors more gracefully
        return res.status(500).json({
            success: false,
            message: 'An error occurred while fetching the profile. Please try again later.',
        });
    }
};
// const updateProfile = async (req, res) => {
//     try {
//         // Ensure the user is authenticated
//         if (!req.user || !req.user.userId) {
//             return res.status(401).json({
//                 success: false,
//                 message: 'Unauthorized access. User not authenticated.',
//             });
//         }

//         const userId = req.user.userId;

//         // Extract updated fields from the request body
//         const { fullName, email, phone, bikeName, address, about } = req.body;

//         // Prepare the fields to be updated
//         const updateFields = {};
//         if (fullName) updateFields.fullName = fullName;
//         if (email) updateFields.email = email;
//         if (phone) updateFields.phone = phone;
//         if (bikeName) updateFields.bikeName = bikeName;
//         if (address) updateFields.address = address;
//         if (about) updateFields.about = about;

//         // Handle profile image upload (if an image is provided)
//         if (req.file) {
//             updateFields.image = req.file.path;  // Assuming you're saving the file path in DB
//         }

//         // Update user in the database
//         const updatedUser = await User.findByIdAndUpdate(userId, updateFields, { new: true }).select('-password -verificationCode -verificationCodeValidation');

//         if (!updatedUser) {
//             return res.status(404).json({
//                 success: false,
//                 message: 'User not found!',
//             });
//         }

//         // Return the updated profile
//         return res.status(200).json({
//             success: true,
//             message: 'Profile updated successfully!',
//             user: updatedUser,
//         });
//     } catch (error) {
//         console.error('Error updating user profile:', error.message);
//         return res.status(500).json({
//             success: false,
//             message: 'An error occurred while updating the profile. Please try again later.',
//         });
//     }
// };

const updateProfile = async (req, res) => {
    try {
        if (!req.user || !req.user.userId) {
            return res.status(401).json({ success: false, message: 'Unauthorized access. User not authenticated.' });
        }

        const userId = req.user.userId;
        const { fullName, email, phone, bikeName, address, about } = req.body;

        const updateFields = {};
        if (fullName) updateFields.fullName = fullName;
        if (email) updateFields.email = email;
        if (phone) updateFields.phone = phone;
        if (bikeName) updateFields.bikeName = bikeName;
        if (address) updateFields.address = address;
        if (about) updateFields.about = about;

        if (req.files && req.files.image && req.files.image[0]) {
            updateFields.image = req.files.image[0].path;
        }

        const updatedUser = await User.findByIdAndUpdate(userId, updateFields, { new: true })
            .select('-password -verificationCode -verificationCodeValidation');

        if (!updatedUser) {
            return res.status(404).json({ success: false, message: 'User not found!' });
        }
        console.log('Files:', req.files);
console.log('Body:', req.body);


        return res.status(200).json({
            success: true,
            message: 'Profile updated successfully!',
            user: updatedUser,
        });
    } catch (error) {
        console.error('Error updating user profile:', error.message);
        return res.status(500).json({
            success: false,
            message: 'An error occurred while updating the profile. Please try again later.',
        });
    }
};


module.exports = {
    signup,
    signin,
    verifyForgotPasswordCode,
    sendForgotPasswordCode,
    changePassword,
    sendVerificationCode,
    verifyVerificationCode,
    verifyOtp,
    getProfile,
    updateProfile
};