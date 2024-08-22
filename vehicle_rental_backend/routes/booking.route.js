const router = require('express').Router();
const controller = require('../modules/booking/booking.controller');
const { verifyUser, verifyAuthorization,verifyRecaptcha } = require('../middlewares/auth.middlerware');

// router.post('/', controller.addData);
router.post('/create-intent', verifyUser,verifyRecaptcha, controller.createPaymentIntent);
router.get('/payment-success/:id', controller.successPayment);
router.get('/', verifyUser, verifyAuthorization, controller.getAllBookings);
router.get('/my-booking', verifyUser, controller.getMyBooking);
router.get('/booking-for-owner', verifyUser, controller.getBookingForOwner);
router.get('/my-booking-transaction', verifyUser, controller.getMyBookingTransaction);
router.get('/my-income-transaction', verifyUser, controller.getMyIncomeTransaction);
router.put('/:id', verifyUser, controller.updateBooking);

module.exports = router;