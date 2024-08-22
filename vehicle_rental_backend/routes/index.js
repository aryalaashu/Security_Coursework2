const router = require("express").Router()

router.use('/user', require("./user.route"))
router.use('/vehicle', require("./vehicle.route"))
router.use('/review', require("./review.route"))
router.use('/contact', require("./contact.route"))
router.use('/booking', require("./booking.route"))


module.exports = router