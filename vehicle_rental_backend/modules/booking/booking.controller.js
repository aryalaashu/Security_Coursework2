const Booking = require('./booking.model');
const httpStatus = require('http-status');
const Joi = require('joi');
const { default: Stripe } = require('stripe');
const vehicleModel = require('../vehicle/vehicle.model');
const userModel = require('../users/user.model');
const stripe = require('stripe')(process.env.STRIPE_KEY);

const bookingJoiSchema = Joi.object({
  vehicle: Joi.string().required(),
  price: Joi.number().required(),
  pickup_date: Joi.string().required(),
  drop_date: Joi.string().required(),
  address: Joi.string().required(),
  contact: Joi.string().required(),
  recaptchaToken: Joi.string().required(),
});

//payment
exports.createPaymentIntent = async (req, res, next) => {
  try {
    // const customer = await stripe.customers.create({
    //   email: 'testingPayment@gmail.com'
    // })
    const { error } = await bookingJoiSchema.validate(req.body);
    if (error) {
      return res.status(httpStatus.BAD_REQUEST).json({
        success: false,
        msg: error.message
      });
    }


    const getVehicle = await vehicleModel.findById(req.body.vehicle);
    if (!getVehicle) return res.status(httpStatus.NOT_FOUND).json({
      success: false,
      msg: "Vehicle Not Found!!"
    });

    // if(getVehicle.user._id === req.user._id){
    //   return res.status(httpStatus.CONFLICT).json({
    //     success: false,
    //     msg: "Cannot Book your own Vehicle.!!"
    //   });
    // }
    req.body.user = req.user._id;
    req.body.vehicle = getVehicle._id;
    const booking = await Booking.create(req.body);
    const lineItems = [
      {
        price_data: {
          currency: "npr",
          product_data: {
            name: getVehicle.name,
          },
          unit_amount: req.body.price * 100,
        },
        quantity: 1

      }
    ];

    const session = await stripe.checkout.sessions.create({
      payment_method_types: ["card"],
      line_items: lineItems,
      mode: "payment",
      success_url: `http://localhost:${process.env.PORT}/api/booking/payment-success/${booking._id}`,
      cancel_url: "http://localhost:3000/failure",
    });

    res.json({ id: session.id, url: session.url });
  } catch (error) {
    console.log(error);
    return res.status(httpStatus.INTERNAL_SERVER_ERROR).json({
      success: false,
      msg: "Something went wrong!!"
    });
  }
};


exports.successPayment = async (req, res, next) => {
  try {
    const booking = await Booking.findById(req.params.id);
    if (!booking) return res.status(httpStatus.NOT_FOUND).json({
      success: false,
      msg: "Booking Not Found!!"
    });

    booking.is_payed = true;
    //send notice
    await booking.save();
    return res.redirect(301, 'http://localhost:3000/success');
  } catch (error) {
    return res.status(httpStatus.INTERNAL_SERVER_ERROR).json({
      success: false,
      msg: "Something went wrong!!"
    });
  }
};

// @route GET booking/
// @desc get all bookings
exports.getAllBookings = async (req, res, next) => {
  try {
    let { page = 1, size = 10, sort = { _id: -1 } } = req.query;
    let searchQuery = {
      is_deleted: false
    };
    if (req.query.email) {
      const user = await userModel.distinct('_id', {
        email: {
          $regex: req.query.email, $options: 'i'
        }
      });
      searchQuery = {
        ...searchQuery,
        user: { $in: user }
      };
    }
    populate = [
      {
        path: 'user',
        select: 'firstname lastname email contact'
      },
      {
        path: 'vehicle',
        select: 'name images description sku price engine year model type fuel_type'
      }
    ];
    const bookings = await Booking.find(searchQuery).select("-__v -is_deleted -updatedAt").populate(populate).skip((page - 1) * size).limit(size).sort(sort).lean();
    const totalCount = await Booking.countDocuments({
      is_deleted: false
    });

    return res.status(httpStatus.OK).json({
      success: true,
      msg: "Bookings!!",
      data: bookings,
      totalCount,
      size: parseInt(size),
      page: parseInt(page)
    });

  } catch (error) {
    console.log(error);
    return res.status(httpStatus.INTERNAL_SERVER_ERROR).json({
      success: false,
      msg: "Failed to fetch booking!!"
    });
  }
};

// @route GET booking/my-booking
// @desc get my booking
exports.getMyBooking = async (req, res, next) => {
  try {
    let { page = 1, size = 10, sort = { _id: -1 } } = req.query;
    let searchQuery = {
      user: req.user._id,
      is_payed: true,
      is_deleted: false
    };
    populate = [
      {
        path: 'user',
        select: 'firstname lastname email contact'
      },
      {
        path: 'vehicle',
        select: 'name images description sku price engine year model type fuel_type'
      }
    ];

    const bookings = await Booking.find(searchQuery).select("-__v -is_deleted -updatedAt").populate([
      {
        path: 'user',
        select: 'firstname lastname email contact'
      },
      {
        path: 'vehicle',
        select: 'name images description sku price engine year model type fuel_type'
      }
    ]).skip((page - 1) * size).limit(size).sort(sort).lean();
    const totalCount = await Booking.countDocuments({
      is_deleted: false
    });

    return res.status(httpStatus.OK).json({
      success: true,
      msg: "My Bookings!!",
      data: bookings,
      totalCount,
      size: parseInt(size),
      page: parseInt(page)
    });
  } catch (error) {
    console.log(error);
    return res.status(httpStatus.INTERNAL_SERVER_ERROR).json({
      success: false,
      msg: "Something went wrong!!"
    });
  }
};

// @route GET booking/booking-for-owner
// @desc get my booking
exports.getBookingForOwner = async (req, res, next) => {
  try {
    let { page = 1, size = 10, sort = { _id: -1 } } = req.query;
    let vehicleId = await vehicleModel.distinct('_id', {
      user: req.user._id
    });
    let searchQuery = {
      vehicle: vehicleId,
      is_payed: true,
      is_deleted: false
    };
    populate = [
      {
        path: 'user',
        select: 'firstname lastname email contact'
      },
      {
        path: 'vehicle',
        select: 'name images description sku price engine year model type fuel_type'
      }
    ];
    const bookings = await Booking.find(searchQuery).select("-__v -is_deleted -updatedAt").populate(populate).skip((page - 1) * size).limit(size).sort(sort).lean();
    const totalCount = await Booking.countDocuments({
      is_deleted: false
    });

    return res.status(httpStatus.OK).json({
      success: true,
      msg: "Bookings For Owner!!",
      data: bookings,
      totalCount,
      size: parseInt(size),
      page: parseInt(page)
    });
  } catch (error) {
    return res.status(httpStatus.INTERNAL_SERVER_ERROR).json({
      success: false,
      msg: "Something went wrong!!"
    });
  }
};

exports.getMyBookingTransaction = async (req, res, next) => {
  try {
    const result = await Booking.aggregate([
      {
        $match: {
          user: req.user._id
        }
      },
      {
        $group: {
          _id: "null",
          totalBooking: { $sum: 1 },
          totalAmount: { $sum: "$price" },
        }
      }
    ]);
    const vtResult = await Booking.aggregate([
      {
        $match: {
          user: req.user._id
        }
      },
      {
        $lookup: {
          from: 'vehicles',
          localField: 'vehicle',
          foreignField: '_id',
          "as": "vehicle"
        }
      },
      {
        $unwind: {
          path: '$vehicle'
        }
      },
      {
        $group: {
          _id: "$vehicle.type",
          totalBooking: { $sum: 1 },
          totalAmount: { $sum: "$price" },
        }
      }
    ]);

    return res.status(httpStatus.OK).json({
      messages: "My Booking Transaction!!",
      result: [...result, ...vtResult],
      success: true
    });
  } catch (error) {
    console.log(error);
    return res.status(httpStatus.INTERNAL_SERVER_ERROR).json({
      messages: "Something went wrong!!",
      success: false
    });
  }
};

exports.getMyIncomeTransaction = async (req, res, next) => {
  try {
    const myVehicle = await vehicleModel.distinct('_id', {user: req.user._id})
    const result = await Booking.aggregate([
      {
        $match: {
          vehicle: {$in: myVehicle}
        }
      },
      {
        $group: {
          _id: "null",
          totalBooking: { $sum: 1 },
          totalAmount: { $sum: "$price" },
        }
      }
    ]);
    const vtResult = await Booking.aggregate([
      {
        $match: {
          vehicle: {$in: myVehicle}
        }
      },
      {
        $lookup: {
          from: 'vehicles',
          localField: 'vehicle',
          foreignField: '_id',
          "as": "vehicle"
        }
      },
      {
        $unwind: {
          path: '$vehicle'
        }
      },
      {
        $group: {
          _id: "$vehicle.type",
          totalBooking: { $sum: 1 },
          totalAmount: { $sum: "$price" },
        }
      }
    ]);

    return res.status(httpStatus.OK).json({
      messages: "My Income Transaction!!",
      result: [...result, ...vtResult],
      success: true
    });
  } catch (error) {
    console.log(error);
    return res.status(httpStatus.INTERNAL_SERVER_ERROR).json({
      messages: "Something went wrong!!",
      success: false
    });
  }
};

exports.updateBooking = async (req, res) => {
  try {
    const bookingId = req.params.id;

    await Booking.findByIdAndUpdate(bookingId, {
      $set: req.body
    });

    return res.status(httpStatus.OK).json({
      success: true,
      msg: "Bookings Status Updated!!",
    });
  } catch (error) {
    return res.status(httpStatus.INTERNAL_SERVER_ERROR).json({
      success: false,
      msg: "Something went wrong!!"
    });
  }
};
