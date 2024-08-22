const mongoose = require('mongoose');
const reviewModel = require('../reviews/review.model');
const Schema = mongoose.Schema;

const VehicleSchema = new Schema({
    name: { type: String, required: true },
    description: { type: String },
    type: { type: String, enum: ['two-wheeler', 'four-wheeler'] },
    seat: { type: Number },
    sku: { type: String, required: true, unique: true },
    price: {
        type: Number, min: 0
    },
    engine: { type: String },
    year: { type: String },
    model: { type: String },
    mileage: { type: String },
    fuel_type: { type: String, enum: ['diesel', 'petrol', 'electric'] },
    images: [{ type: String }],
    user: { type: Schema.Types.ObjectId, ref: 'User' },
    is_active: { type: Boolean, default: false },
    is_deleted: { type: Boolean, default: false },
},
    {
        timestamps: true
    });
const getRating = async (vehicle) => {
    const rating = await reviewModel.aggregate([
        { $match: { vehicle: vehicle } },
        {
            $group: {
                _id: null,
                rating: { $avg: '$rating' }
            }
        },
    ]);
    return rating.length ? rating[0].rating : 0;
};

VehicleSchema.post('find', async (result, next) => {
    try {
        // const results = []
        const tests = await Promise.all(result.map(async value=> {
            if(value instanceof mongoose.Document){
                value = value.toJSON()
            }
            value.rating = await getRating(value._id);
            return value
        }))
        return tests;
    } catch (error) {
        next(error);
    }
});

VehicleSchema.post('findOne', async (result, next) => {
    try {
        if(result){
            result.rating = await getRating(result._id);
        }
        return result;
    } catch (error) {
        next(error);
    }
});

module.exports = mongoose.model('Vehicle', VehicleSchema);
