const Joi = require("joi");
const httpStatus = require("http-status");
const userModel = require("./user.model");
// const cartModel = require("../carts/cart.model");
const bcrypt = require('bcryptjs');
const jwt = require("jsonwebtoken");
const upload = require("../../middlewares/upload");

class UserController {
    userValidationSchema = Joi.object({
        firstname: Joi.string().required(),
        lastname: Joi.string().required(),
        email: Joi.string().email().required(),
        password: Joi.string().required(),
        contact: Joi.number().required(),
        address: Joi.string().required(),
    });

    loginValidationSchema = Joi.object({
        email: Joi.string().email().required(),
        password: Joi.string().required(),
        recaptchaToken: Joi.string().required(),
    });

    // createCart = async (user) => {
    //     try {
    //         //check if active cart exists
    //         const activeCart = await cartModel.findOne({
    //             user_id: user._id,
    //             status: "CART"
    //         });
    //         if (activeCart) return;

    //         //get cart_no 
    //         const result = await cartModel.findOne({}).sort({ _id: -1 });
    //         console.log("result", result);
    //         const cart_no = result ? result.cart_no + 1 : 1000;

    //         const cart = await cartModel.create({ cart_no, user_id: user._id });
    //     } catch (error) {
    //         throw error;
    //     }
    // };

    login = async (req, res, next) => {
        console.log(req.body)
        try {
            const { error } = this.loginValidationSchema.validate(req.body);
            if (error) {
                return res.status(httpStatus.BAD_REQUEST).json({
                    success: false,
                    msg: error.message
                });
            }
    
            const user = await userModel.findOne({
                email: req.body.email,
                is_deleted: false
            }).lean();
    
            if (!user) {
                return res.status(httpStatus.NOT_FOUND).json({
                    success: false,
                    msg: "User Not Registered!!"
                });
            }
    
            // Check if account is locked
            if (user.accountLockedUntil && new Date() < user.accountLockedUntil) {
                return res.status(httpStatus.FORBIDDEN).json({
                    success: false,
                    msg: `Account is locked. Try again after ${user.accountLockedUntil.toLocaleTimeString()}`
                });
            }
    
            // Check if password is valid
            const checkPassword = await bcrypt.compare(req.body.password, user.password);
            if (!checkPassword) {
                await userModel.updateOne(
                    { _id: user._id },
                    { $inc: { loginAttempt: 1 } }
                );
    
                // Lock the account if login attempts exceed 3
                if (user.loginAttempt + 1 >= 3) {
                    const lockTime = new Date();
                    lockTime.setMinutes(lockTime.getMinutes() + 5);
    
                    await userModel.updateOne(
                        { _id: user._id },
                        { $set: { accountLockedUntil: lockTime, loginAttempt: 0 } }
                    );
    
                    return res.status(httpStatus.FORBIDDEN).json({
                        success: false,
                        msg: "Account locked due to too many failed login attempts. Try again after 5 minutes."
                    });
                }
    
                return res.status(httpStatus.NOT_FOUND).json({
                    success: false,
                    msg: "Email or Password Incorrect!!"
                });
            }
            // Store user data in the session
            req.session.userId = user._id;
            req.session.role = user.role;
    
            // Reset login attempts on successful login
            await userModel.updateOne(
                { _id: user._id },
                { $set: { loginAttempt: 0, accountLockedUntil: null } }
            );
    
            // Generate and send a JWT token for the authenticated user
            const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '90d' });
    
            // const { password, __v, ...data } = user;
    
            // return res.status(httpStatus.OK).json({
            //     success: true,
            //     msg: "Login Success!!",
            //     data: {
            //         ...(data),
            //         token
            //     }
            // });

             // Pick only the required fields

        const { _id, firstname, lastname, email, address, contact,role  } = user;

        return res.status(httpStatus.OK).json({
            success: true,
            msg: "Login Success!!",
            data: {
                _id,
                firstname,
                lastname,
                email,
                address,
                contact,
                token,role 
            }
        });


        } catch (error) {
            console.log("error", error);
            return res.status(httpStatus.INTERNAL_SERVER_ERROR).json({
                success: false,
                msg: "Something Went Wrong!!"
            });
        }
    };
    
    register = async (req, res, next) => {
        try {
            const { error } = this.userValidationSchema.validate(req.body);
            if (error) {
                return res.status(httpStatus.BAD_REQUEST).json({
                    success: false,
                    msg: error.message
                });
            }
    
            const checkUserExist = await userModel.findOne({
                email: req.body.email,
                is_deleted: false
            });
            if (checkUserExist) {
                return res.status(httpStatus.CONFLICT).json({
                    success: false,
                    msg: "User Already Exists!!"
                });
            }
    
            bcrypt.genSalt(10, async (error, salt) => {
                if (error) {
                    return res.status(httpStatus.INTERNAL_SERVER_ERROR).json({
                        success: false,
                        msg: "Error generating salt!!"
                    });
                }
                bcrypt.hash(req.body.password, salt, async (error, hash) => {
                    if (error) {
                        return res.status(httpStatus.INTERNAL_SERVER_ERROR).json({
                            success: false,
                            msg: "Error hashing password!!"
                        });
                    }
                    const user = await userModel.create({ 
                        ...req.body, 
                        password: hash, 
                        oldPasswords: [hash] 
                    });
    
                    if (user) {
                        return res.status(httpStatus.OK).json({
                            success: true,
                            msg: 'Registration Completed'
                        });
                    } else {
                        return res.status(httpStatus.INTERNAL_SERVER_ERROR).json({
                            success: false,
                            msg: "Failed to Register!!"
                        });
                    }
                });
            });
        } catch (error) {
            return res.status(httpStatus.INTERNAL_SERVER_ERROR).json({
                success: false,
                msg: "Something Went Wrong!!"
            });
        }
    };
    

    allUser = async (req, res, next) => {
        try {
            const { page = 1, size = 10, sort = 
            {_id:-1} } = req.query;

            let searchQuery = {
                is_deleted: false
            };

            if (req.query.search) {
                searchQuery = {
                    ...searchQuery,
                    $or: [{
                        firstname: { $regex: req.query.search, $options: 'i' }
                    },{
                        lastname: { $regex: req.query.search, $options: 'i' }
                    }]
                };
            }

            const users = await userModel.find(searchQuery).select("firstname lastname email contact address").skip((page - 1) * size).limit(size).sort(sort);

            const totalCount = await userModel.countDocuments({is_deleted: false})
            return res.status(httpStatus.OK).json({
                success: true,
                msg: "Users!!",
                data: users,
                page,
                size,
                totalCount
            });

        } catch (error) {
            return res.status(httpStatus.INTERNAL_SERVER_ERROR).json({
                success: false,
                msg: "Something Went Wrong!!"
            });
        }
    };

    myProfile = async (req, res, next) => {
        try {
            const { password, role, is_deleted, createdAt, updatedAt, __v, ...data } = req.user;
            return res.status(httpStatus.OK).json({
                success: true,
                msg: "User!!",
                data: data
            });
        } catch (error) {
            return res.status(httpStatus.INTERNAL_SERVER_ERROR).json({
                success: false,
                msg: "Something Went Wrong!!"
            });
        }
    };

    updateProfile = async (req, res, next) => {
        try {
            const id = req.params.id;
            const user = await userModel.findById(id);
            if (!user) {
                return res.status(httpStatus.NOT_FOUND).json({
                    success: false,
                    msg: "User Not Registered!!"
                });
            }

            await userModel.findByIdAndUpdate(
                id,
                req.body,
                { new: true }
            );

            return res.status(httpStatus.OK).json({
                success: true,
                msg: "User Profile Updated!!"
            });
        } catch (error) {
            return res.status(httpStatus.INTERNAL_SERVER_ERROR).json({
                success: false,
                msg: "Something Went Wrong!!"
            });
        }
    };

    deleteUser = async (req, res, next) => {
        try {
            const id = req.params.id;
            const user = await userModel.findById(id);
            if (!user) {
                return res.status(httpStatus.NOT_FOUND).json({
                    success: false,
                    msg: "User Not Registered!!"
                });
            }

            user.is_deleted = true;
            await user.save();

            return res.status(httpStatus.OK).json({
                success: true,
                msg: "User Deleted!!"
            });
        } catch (error) {
            return res.status(httpStatus.INTERNAL_SERVER_ERROR).json({
                success: false,
                msg: "Something Went Wrong!!"
            });
        }
    };

    uploadPP = async (req, res) => {
        upload.single('image')(req, res, async error => {
            if (error) {
                return res.status(httpStatus.BAD_REQUEST).json({
                    success: false,
                    msg: error.message
                });
            }
            try {
                console.log("req.file", req.file)
                await userModel.findByIdAndUpdate(req.user._id, {
                    image: req.file ? req.file.path : ''   
                })
                return res.status(httpStatus.OK).json({
                    success: true,
                    msg: "Profile Image Updated!!",
                    data: {
                        image: req.file ? req.file.path : '' 
                    }
                });
            } catch (error) {
                console.log("error", error)
                return res.status(httpStatus.INTERNAL_SERVER_ERROR).json({
                    success: false,
                    msg: "Something Went Wrong!!"
                });
            }
        });
    };

    // changePassword = async (req, res) => {
    //     try {
    //         const {oldpassword, newpassword} = req.body

    //         //check if old password matches
    //         const checkPassword = await bcrypt.compare(oldpassword, req.user.password)
    //         if(!checkPassword){
    //             return res.status(httpStatus.UNAUTHORIZED).json({
    //                 success: false,
    //                 msg: "Invalid Credential!!"
    //             });
    //         }
    //         bcrypt.genSalt(10, async (error, salt) => {
    //             bcrypt.hash(newpassword, salt, async (error, hash) => {
    //                 await userModel.findByIdAndUpdate(req.user._id, {
    //                     password: hash
    //                 },{new: true})
    //             });
    //         });
    //         return res.status(httpStatus.OK).json({
    //             success: true,
    //             msg: "Password Changed!!"
    //         })
    //     } catch (error) {
    //         console.log("error", error)
    //             return res.status(httpStatus.INTERNAL_SERVER_ERROR).json({
    //                 success: false,
    //                 msg: "Something Went Wrong!!"
    //             });
    //     }
    // }

    changePassword = async (req, res) => {
        try {
            const { oldpassword, password } = req.body;
            console.log(req.body)
    
            // Ensure req.user.oldPasswords is an array
            const oldPasswords = req.user.oldPasswords || [];
            console.log(oldpassword)
            console.log(password)
    
            // Check if the old password matches the current password
            if ( !oldpassword || !password) {
                return res.status(httpStatus.BAD_REQUEST).json({
                    success: false,
                    msg: "Required fields are missing!"
                });
            }
    
            const checkPassword = await bcrypt.compare(oldpassword, req.user.password);
            if (!checkPassword) {
                return res.status(httpStatus.UNAUTHORIZED).json({
                    success: false,
                    msg: "Invalid Credential!!"
                });
            }
    
            // Check if the new password matches any of the old passwords
            for (let oldHash of oldPasswords) {
                if (oldHash) {  // Ensure oldHash is defined
                    const isMatch = await bcrypt.compare(password, oldHash);
                    if (isMatch) {
                        return res.status(httpStatus.BAD_REQUEST).json({
                            success: false,
                            msg: "Cannot use old password!"
                        });
                    }
                }
            }
    
            // Hash the new password and update the user's password and oldPasswords array
            bcrypt.genSalt(10, async (error, salt) => {
                if (error) {
                    return res.status(httpStatus.INTERNAL_SERVER_ERROR).json({
                        success: false,
                        msg: "Error generating salt!"
                    });
                }
    
                bcrypt.hash(password, salt, async (error, hash) => {
                    if (error) {
                        return res.status(httpStatus.INTERNAL_SERVER_ERROR).json({
                            success: false,
                            msg: "Error hashing password!"
                        });
                    }
    
                    // Update the user's password and oldPasswords array
                    const updatedUser = await userModel.findByIdAndUpdate(
                        req.user._id,
                        {
                            password: hash,
                            $push: { oldPasswords: { $each: [hash], $slice: -3 } } // Keep only the last 3 passwords
                        },
                        { new: true }
                    );
    
                    if (updatedUser) {
                        return res.status(httpStatus.OK).json({
                            success: true,
                            msg: "Password Changed!!"
                        });
                    } else {
                        return res.status(httpStatus.INTERNAL_SERVER_ERROR).json({
                            success: false,
                            msg: "Failed to update password!"
                        });
                    }
                });
            });
        } catch (error) {
            console.log("error", error);
            return res.status(httpStatus.INTERNAL_SERVER_ERROR).json({
                success: false,
                msg: "Something Went Wrong!!"
            });
        }
    };
    
    
}

module.exports = UserController;