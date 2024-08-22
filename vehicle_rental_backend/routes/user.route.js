const UserController = require("../modules/users/user.controller");
const { verifyUser, verifyAuthorization,loginRateLimiter,verifyRecaptcha,sigupRateLimiter } = require("../middlewares/auth.middlerware");

const router = require("express").Router()
const userController = new UserController()

router.post('/login',loginRateLimiter, verifyRecaptcha, userController.login)

router.post('/register',sigupRateLimiter, userController.register)

router.get('/all', verifyUser, verifyAuthorization, userController.allUser)

router.get('/my-profile', verifyUser, userController.myProfile)

router.put('/update-profile/:id', verifyUser, userController.updateProfile)

router.put('/upload-pp', verifyUser, userController.uploadPP)

router.put('/change-password', verifyUser, userController.changePassword)

router.delete('/delete-user/:id', verifyUser, verifyAuthorization, userController.deleteUser)


module.exports = router