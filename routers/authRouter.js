const express = require('express');
const authController = require('../controllers/authController');
const { identifier,authenticateToken } = require('../middlewares/identification');
const upload = require('../middlewares/multer');

//const {authenticate} = require('../middlewares/')
const router = express.Router();
router.post('/signup', authController.signup);
router.post('/verify-otp', authController.verifyOtp);
router.post('/signin', authController.signin);
// router.post('/signout', identifier, authController.signout);
router.get('/profile', identifier, authController.getProfile);


router.patch(
	'/send-verification-code',
	identifier,
	authController.sendVerificationCode
);
router.patch(
	'/verify-verification-code',
	identifier,
	authController.verifyVerificationCode
);
router.patch('/change-password', identifier, authController.changePassword);
router.patch(
	'/send-forgot-password-code',
	authController.sendForgotPasswordCode
);
router.patch(
	'/verify-forgot-password-code',
	authController.verifyForgotPasswordCode
);

 router.put('/uploadprofile',identifier,upload.fields([{ name: 'program', maxCount: 1 }, { name: 'image', maxCount: 1 }]),authController.updateProfile);

module.exports = router;
