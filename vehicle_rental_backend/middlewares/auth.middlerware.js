const jwt = require('jsonwebtoken');
const httpStatus = require('http-status');
const userModel = require('../modules/users/user.model');
const axios = require('axios');

const decodeToken = (authorization) => {
  try {
    const token = authorization.split(' ')[1];
    return jwt.verify(token, process.env.JWT_SECRET);
  } catch (error) {
    return null;
  }
};

const getUser = async (userId) => {
  try {
    return await userModel.findById(userId).lean();
  } catch (error) {
    return null;
  }
};


const handleUnauthorizedAccess = (res) => {
  return res
    .status(httpStatus.UNAUTHORIZED)
    .json({ success: false, message: 'Unauthorized access' });
};

const verifyUser = async (req, res, next) => {
  if (req.headers.authorization === undefined) {
    return handleUnauthorizedAccess(res);
  }
  let decodedResult = decodeToken(req.headers.authorization);
  if (decodedResult == null || decodedResult == undefined)
    return handleUnauthorizedAccess(res);

  let userData = await getUser(decodedResult.userId);
  if (userData == null) return handleUnauthorizedAccess(res);
  req.user = userData;
  next();
};

const verifyAuthorization = (req, res, next) => {
  const role = req.user.role
  if (role.includes('admin') || role.includes('superadmin')) {
    next();
  }else{
    return handleUnauthorizedAccess(res);
  }
};


const rateLimit = require('express-rate-limit');

// Define rate limiter middleware
const loginRateLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    max: 5, 
    message: {
        success: false,
        msg: 'Too many login attempts from this IP, please try again after 15 minutes'
    },
    headers: true, 
});

const sigupRateLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, 
  max: 1, 
  message: {
      success: false,
      msg: 'Too many register attempts from this IP, please try again after 15 minutes'
  },
  headers: true, 
});

const verifyRecaptcha = async (req, res, next) => {
  console.log(req.body)
  const recaptchaResponse = req.body['recaptchaToken']; 


  if (!recaptchaResponse) {
    return res.status(httpStatus.BAD_REQUEST).json({
      success: false,
      message: 'reCAPTCHA response is required'
    });
  }

  try {
    const secretKey = process.env.RECAPTCHA_SECRET_KEY; 
    const response = await axios.post(`https://www.google.com/recaptcha/api/siteverify`, null, {
      params: {
        secret: secretKey,
        response: recaptchaResponse
      }
    });

    const data = response.data;
    console.log(data)
    if (data.success) {
      next(); 
    } else {
      res.status(httpStatus.UNAUTHORIZED).json({
        success: false,
        message: 'reCAPTCHA verification failed'
      });
    }
  } catch (error) {
    console.error('Error verifying reCAPTCHA:', error);
    res.status(httpStatus.INTERNAL_SERVER_ERROR).json({
      success: false,
      message: 'Error verifying reCAPTCHA'
    });
  }
};
module.exports = { verifyUser, verifyAuthorization,loginRateLimiter,verifyRecaptcha,sigupRateLimiter };
