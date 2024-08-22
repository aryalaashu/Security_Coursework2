const httpStatus = require("http-status");
const vehicleModel = require("./vehicle.model");
const Joi = require("joi");
const upload = require("../../middlewares/upload");
const bookingModel = require("../booking/booking.model");
// const reviewModel = require("../reviews/review.model");

class VehicleController {
    // constructor(){
    //     this.counter = 1
    // }
    vehicleValidationSchema = Joi.object({
        name: Joi.string().required(),
        type: Joi.string().required(),
        description: Joi.string().required(),
        price: Joi.number().min(10),
        seat: Joi.number().min(1),
        engine: Joi.string().required(),
        year: Joi.string().required(),
        model: Joi.string().required(),
        mileage: Joi.string().required(),
        fuel_type: Joi.string().required(),
    });


    skuGenerator = async (name) => {
        const formattedName = name.replace(/\s/g, '_'); // Replace spaces with underscores
        const randomNum = Math.floor(Math.random() * 9000) + 1000;
        const sku = formattedName.toUpperCase() + '_' + randomNum;

        const checkSKU = await vehicleModel.findOne({
            sku,
            is_deleted: false,
        });
        if (checkSKU) await this.skuGenerator(name);

        return sku;
    };

    addVehicle = async (req, res) => {
        upload.array('images')(req, res, async err => {
            if (err) {
                return res.status(httpStatus.BAD_REQUEST).json({
                    success: false,
                    msg: err.messages
                });
            }
            try {

                const { error } = this.vehicleValidationSchema.validate(req.body);

                if (error) {
                    return res.status(httpStatus.CONFLICT).json({
                        success: false,
                        msg: error.message
                    });
                }

                //add path image
                const images = await Promise.all(req.files.map(value => value.path));

                req.body.images = images;
                req.body.user = req.user._id;
                // Promise.all(req.files.map(value => {
                //     const variantIndex = variant.findIndex(ele => ele.sku === value.fieldname);
                //     const image = variant[variantIndex].images || []
                //     if (variantIndex >= 0) variant[variantIndex].images = [value.path];
                // }));

                // const checkVehicle = await vehicleModel.findOne({
                //     req.body.name,
                //     is_deleted: false,
                // });

                // if (checkVehicle) {
                //     return res.status(httpStatus.CONFLICT).json({
                //         success: false,
                //         msg: "Vehicle Already Exits!!"
                //     });
                // }
                req.body.sku = await this.skuGenerator(req.body.name);

                const vehicle = await vehicleModel.create(req.body);

                return res.status(httpStatus.OK).json({
                    success: true,
                    msg: "Vehicle Added",
                    data: vehicle
                });
            } catch (error) {
                console.log("error", error);
                return res.status(httpStatus.INTERNAL_SERVER_ERROR).json({
                    success: false,
                    msg: "Something Went Wrong!!"
                });
            }

        });
    };

    getVehicles = async (req, res) => {
        try {

            let { page = 1, size = 10, sort = { _id: -1 } } = req.query;
            let searchQuery = {
                is_deleted: false,
                is_active: true,
            };

            if (req.query.price) {
                sort = {
                    // ...sort,
                    'price': parseInt(req.query.price)
                };
            }

            if (req.query.type) {
                searchQuery = {
                    ...searchQuery,
                    type: req.query.type
                };
            }

            if (req.query.min & req.query.max) {
                searchQuery = {
                    ...searchQuery,
                    $and: [
                        { price: { $gte: req.query.min } },
                        { price: { $lte: req.query.max } }
                    ]
                    // parseInt(req.query.price)
                };
            }

            if (req.query.search) {
                searchQuery = {
                    ...searchQuery,
                    name: { $regex: req.query.search, $options: 'i' }
                };
            }

            const vehicles = await vehicleModel.find(searchQuery).select("name description type sku price user images engine seat year model mileage fuel_type is_active").populate({
                path: "user",
                select: "firstname lastname email contact address"
            }).skip((page - 1) * size).limit(size).sort(sort).lean();

            const totalCount = await vehicleModel.countDocuments(searchQuery);

            return res.status(httpStatus.OK).json({
                success: true,
                msg: "Vehicles!!",
                data: vehicles,
                totalCount,
                size: parseInt(size),
                page: parseInt(page)
            });
        } catch (error) {
            console.log("err", error);
            return res.status(httpStatus.INTERNAL_SERVER_ERROR).json({
                success: false,
                msg: "Something Went Wrong!!"
            });
        }
    };

    getMyVehicles = async (req, res) => {
        try {
            let { page = 1, size = 10, sort = { _id: -1 } } = req.query;
            let searchQuery = {
                is_deleted: false,
                user: req.user._id
            };

            if (req.query.price) {
                sort = {
                    // ...sort,
                    'price': parseInt(req.query.price)
                };
            }

            if (req.query.type) {
                searchQuery = {
                    ...searchQuery,
                    type: req.query.type
                };
            }

            if (req.query.min & req.query.max) {
                searchQuery = {
                    ...searchQuery,
                    $and: [
                        { price: { $gte: req.query.min } },
                        { price: { $lte: req.query.max } }
                    ]
                    // parseInt(req.query.price)
                };
            }

            if (req.query.search) {
                searchQuery = {
                    ...searchQuery,
                    name: { $regex: req.query.search, $options: 'i' }
                };
            }

            const vehicles = await vehicleModel.find(searchQuery).select("name description type sku price user images engine seat year model mileage fuel_type is_active").populate({
                path: "user",
                select: "firstname lastname email contact address"
            }).skip((page - 1) * size).limit(size).sort(sort).lean();

            const totalCount = await vehicleModel.countDocuments(searchQuery);

            return res.status(httpStatus.OK).json({
                success: true,
                msg: "Vehicles!!",
                data: vehicles,
                totalCount,
                size: parseInt(size),
                page: parseInt(page)
            });
        } catch (error) {
            console.log("err", error);
            return res.status(httpStatus.INTERNAL_SERVER_ERROR).json({
                success: false,
                msg: "Something Went Wrong!!"
            });
        }
    };
    getUnverifiedVehicles = async (req, res) => {
        try {
            let { page = 1, size = 10, sort = { _id: -1 } } = req.query;
            let searchQuery = {
                is_deleted: false,
                is_active: false
            };

            if (req.query.price) {
                sort = {
                    // ...sort,
                    'price': parseInt(req.query.price)
                };
            }

            if (req.query.type) {
                searchQuery = {
                    ...searchQuery,
                    type: req.query.type
                };
            }

            if (req.query.min & req.query.max) {
                searchQuery = {
                    ...searchQuery,
                    $and: [
                        { price: { $gte: req.query.min } },
                        { price: { $lte: req.query.max } }
                    ]
                    // parseInt(req.query.price)
                };
            }

            if (req.query.search) {
                searchQuery = {
                    ...searchQuery,
                    name: { $regex: req.query.search, $options: 'i' }
                };
            }

            const vehicles = await vehicleModel.find(searchQuery).select("name description type sku price user images engine seat year model mileage fuel_type is_active").populate({
                path: "user",
                select: "firstname lastname email contact address"
            }).skip((page - 1) * size).limit(size).sort(sort).lean();

            const totalCount = await vehicleModel.countDocuments(searchQuery);

            return res.status(httpStatus.OK).json({
                success: true,
                msg: "Vehicles!!",
                data: vehicles,
                totalCount,
                size: parseInt(size),
                page: parseInt(page)
            });
        } catch (error) {
            console.log("err", error);
            return res.status(httpStatus.INTERNAL_SERVER_ERROR).json({
                success: false,
                msg: "Something Went Wrong!!"
            });
        }
    };

    getVehicle = async (req, res) => {
        try {
            const sku = req.params.sku;
            const vehicle = await vehicleModel.findOne({
                sku: sku
            }).select("name description type sku price user images engine seat year model mileage fuel_type is_active").populate({
                path: "user",
                select: "firstname lastname email contact address"
            }).lean();
            if (!vehicle) {
                return res.status(httpStatus.NOT_FOUND).json({
                    success: false,
                    msg: "Vehicle Not Found!!"
                });
            }
            // const rating = await reviewModel.aggregate([
            //     { $match: { vehicle: vehicle._id } },
            //     {
            //         $group: {
            //             _id: null,
            //             rating: { $avg: '$rating' }
            //         }
            //     },
            // ]);

            // vehicle = vehicle.toJSON();
            // vehicle.rating = rating.length ? rating[0].rating : 0;
            return res.status(httpStatus.OK).json({
                success: true,
                msg: "Vehicle!!",
                data: vehicle
            });
        } catch (error) {
            return res.status(httpStatus.INTERNAL_SERVER_ERROR).json({
                success: false,
                msg: "Something Went Wrong!!"
            });
        }
    };

    updateVehicle = async (req, res) => {
        upload.any()(req, res, async err => {
            if (err) {
                return res.status(httpStatus.BAD_REQUEST).json({
                    success: false,
                    msg: err.messages
                });
            }

            try {
                const id = req.params.id;
                // req.body.variant = JSON.parse(req.body.variant);

                const vehicle = await vehicleModel.findById(id);
                if (!vehicle) {
                    return res.status(httpStatus.NOT_FOUND).json({
                        success: false,
                        msg: "Vehicle Not Found!!"
                    });
                }

                if (req.body.name && req.body.name !== vehicle.name) {
                    req.body.sku = await this.skuGenerator(req.body.name);
                }

                let images = vehicle.images;
                const toRemove = req.body.replace_images_paths;
                if (toRemove && toRemove.length > 0) {
                    images = images.filter(ele => !toRemove.includes(ele));
                }
                req.body.images = images;
                if (req.files) {
                    const newImages = await Promise.all(req.files.map(value => value.path));
                    req.body.images = images.concat(newImages);

                    //change image
                    // Promise.all(req.files.map(value => {
                    //     const variantIndex = req.body.variant.findIndex(ele => ele.sku === value.fieldname);
                    //     console.log(variantIndex, req.body.variant);
                    //     if (variantIndex >= 0) req.body.variant[variantIndex].images = [value.path];
                    // }));
                }

                const updatedVehicle = await vehicleModel.findByIdAndUpdate(
                    id,
                    req.body,
                    { new: true }
                );
                return res.status(httpStatus.OK).json({
                    success: true,
                    msg: "Vehicle Updated!!",
                    data: updatedVehicle
                });
            } catch (error) {
                console.log("error", error);
                return res.status(httpStatus.INTERNAL_SERVER_ERROR).json({
                    success: false,
                    msg: "Something Went Wrong!!"
                });
            }
        });
    };

    deleteVehicle = async (req, res) => {
        try {
            const id = req.params.id;
            const vehicle = await vehicleModel.findById(id);
            if (!vehicle) {
                return res.status(httpStatus.NOT_FOUND).json({
                    success: false,
                    msg: "Vehicle Not Found!!"
                });
            }

            vehicle.is_deleted = true;
            await vehicle.save();

            return res.status(httpStatus.OK).json({
                success: true,
                msg: "Vehicle Deleted!!"
            });
        } catch (error) {
            console.log(error);
            return res.status(httpStatus.INTERNAL_SERVER_ERROR).json({
                success: false,
                msg: "Something Went Wrong!!"
            });
        }
    };

    verifyVehicle = async (req, res) => {
        try {
            const id = req.params.id;
            const vehicle = await vehicleModel.findById(id);
            if (!vehicle) {
                return res.status(httpStatus.NOT_FOUND).json({
                    success: false,
                    msg: "Vehicle Not Found!!"
                });
            }

            vehicle.is_active = true;
            await vehicle.save();

            return res.status(httpStatus.OK).json({
                success: true,
                msg: "Vehicle Verified!!"
            });
        } catch (error) {
            console.log(error);
            return res.status(httpStatus.INTERNAL_SERVER_ERROR).json({
                success: false,
                msg: "Something Went Wrong!!"
            });
        }
    };

    search = async (req, res) => {
        try {
            const { pickup_date, drop_date, type } = req.query;

            let { page = 1, size = 10, sort = { _id: -1 } } = req.query;
            let searchQuery = {
                is_deleted: false,
                is_active: true,
            };

            let bookedQuery = {
                // $or: [
                //     {
                //         "pickup_date": { "$lte": pickup_date },
                //         "drop_date": { "$gte": pickup_date }
                //     },
                //     {
                //         "pickup_date": { "$gte": drop_date },
                //         "drop_date": { "$lte": drop_date }
                //     },
                // ],
                // {
                "$and": [
                    { "pickup_date": { "$lte": drop_date } },
                    { "drop_date": { "$gte": pickup_date } }
                ],
                //   }
                is_payed: true,
            };

            if (type) {
                searchQuery = {
                    ...searchQuery,
                    type
                };
                bookedQuery = {
                    ...bookedQuery,
                    type
                };
            }

            const getBookedVehicleId = await bookingModel.distinct('vehicle', bookedQuery);

            searchQuery = {
                ...searchQuery,
                _id: { $nin: getBookedVehicleId }
            };

            if (req.query.min & req.query.max) {
                searchQuery = {
                    ...searchQuery,
                    $and: [
                        { price: { $gte: req.query.min } },
                        { price: { $lte: req.query.max } }
                    ]
                    // parseInt(req.query.price)
                };
            }

            if (req.query.search) {
                searchQuery = {
                    ...searchQuery,
                    name: { $regex: req.query.search, $options: 'i' }
                };
            }

            const vehicles = await vehicleModel.find(searchQuery).select("name description type sku price user images engine seat year model mileage fuel_type is_active").populate({
                path: "user",
                select: "firstname lastname email contact address"
            }).skip((page - 1) * size).limit(size).sort(sort).lean();

            const totalCount = await vehicleModel.countDocuments(searchQuery);

            return res.status(httpStatus.OK).json({
                success: true,
                msg: "Vehicles!!",
                data: vehicles,
                totalCount,
                size: parseInt(size),
                page: parseInt(page)
            });
        } catch (error) {
            return res.status(httpStatus.INTERNAL_SERVER_ERROR).json({
                success: false,
                msg: "Something Went Wrong!!"
            });
        }
    };

}

module.exports = VehicleController;

