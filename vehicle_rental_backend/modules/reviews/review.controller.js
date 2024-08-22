const httpStatus = require("http-status");
const Joi = require("joi");
const reviewModel = require("./review.model");
const vehicleModel = require("../vehicle/vehicle.model");


class ReviewController {

    reviewValidationSchema = Joi.object({
        vehicle: Joi.string().required(),
        message: Joi.string().optional(),
        rating: Joi.number().min(0).max(5).required()
    });

    addUpdateReview = async (req, res) => {
        try {
            const { vehicle, rating, message } = req.body;
            const checkVehicle = await vehicleModel.findById(
                vehicle,
            );

            if (!checkVehicle) {
                return res.status(httpStatus.BAD_REQUEST).json({
                    success: false,
                    msg: "Vehicle Not Found!!"
                });
            }

            const {error} = await this.reviewValidationSchema.validate(req.body)
            if (error) {
                return res.status(httpStatus.CONFLICT).json({
                    success: false,
                    msg: error.message
                });
            }

            let review = await reviewModel.findOne({
                user: req.user._id,
                vehicle: checkVehicle._id
            });

            if(review){
                review.rating = rating,
                review.message = message
                await review.save() 
            }else{
                review = await reviewModel.create({
                    vehicle, rating, message, user: req.user._id
                });
            }

            return res.status(httpStatus.OK).json({
                success: true,
                msg: "Rating updated!!",
                data: review
            });

        } catch (error) {
            console.log("error", error);
            return res.status(httpStatus.INTERNAL_SERVER_ERROR).json({
                success: false,
                msg: "Something Went Wrong!!"
            });
        }
    };

    getVehicleReviews = async (req, res) => {
        try {
            const { page = 1, size = 10 } = req.query;

            const reviews = await reviewModel.find({ vehicle: req.params.vehicle }).populate({path:'user', select: '-password -__v -createdAt -updatedAt'}).skip((page - 1) * size).limit(size);

            return res.status(httpStatus.OK).json({
                success: true,
                msg: "Ratings!!",
                data: reviews
            });
        } catch (error) {
            return res.status(httpStatus.INTERNAL_SERVER_ERROR).json({
                success: false,
                msg: "Something Went Wrong!!"
            });
        }
    };

}

module.exports = ReviewController;