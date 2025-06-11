import { Router } from "express";
import * as authController from '../controllers/auth.controller.js'
import multer from 'multer'
import path from 'path'

const router = Router()

router.route('/register').get(authController.getRegisterPage).post(authController.postRegister)

router.route('/login').get(authController.getLoginPage).post(authController.postLogin)

//created a dashboard using json-web-token
router.route('/me').get(authController.getMe)

//clearing cookie here after logout
router.route('/logout').get(authController.getLogoutUser)

router.route('/profile').get(authController.getUserProfilePage)

router.route('/verify-email').get(authController.getVerifyEmailPage)

router.route('/resend-verification-link').post(authController.resendVerificationLink)

router.route('/verify-email-token').get(authController.verifyEmailToken)

//!using multer here for uploading profile, so import first
//?1.given 'destination' and 'filename'
const avatarStorage = multer.diskStorage({
    destination : (req, file, cb) => {
        cb(null, 'public/upload/avatar')  //?here cb means callback to save uploaded profile
    },
    filename : (req, file, cb) => {
        const ext = path.extname(file.originalname);
        cb(null, `${Date.now()}_${Math.random()}${ext}`)  //?setting unique file name
    },
})

//?2.Filter the image type of files
const avatarFileFilter = (req, file, cb) => {
    if(file.mimetype.startsWith('image/')){
        cb(null, true)
    }
    else{
        cb(new Error("Only image file are allowed."), false)
    }
}

const avatarUpload = multer({
    storage : avatarStorage,
    fileFilter : avatarFileFilter,
    limits : {fileSize : 5 * 1025 * 1024} // 5 MB
})

router.route('/edit-profile')
    .get(authController.getEditProfilePage)
    .post(avatarUpload.single('avatar') ,authController.postEditProfile)
// avatarUpload.single('avatar') here avatar is name of input field for uploading profile   

router.route('/change-password').get(authController.getChangePasswordPage).post(authController.postChangePassword)

router.route('/forget-password').get(authController.getForgetPasswordPage).post(authController.postForgetPassword)

router.route('/reset-password/:token').get(authController.resetPasswordTokenPage).post(authController.postResetPasswordToken)

router.route('/google').get(authController.getGoogleLoginPage)

router.route('/google/callback').get(authController.getGoogleLoginCallback)

router.route('/github').get(authController.getGithubLoginPage)

router.route('/github/callback').get(authController.getGithubLoginCallback)

router.route('/set-password').get(authController.getSetPasswordPage).post(authController.postSetPassword)


export const authRouter = router

