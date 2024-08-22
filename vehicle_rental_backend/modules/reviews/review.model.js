const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const ReviewSchema = new Schema({
    vehicle: { type: Schema.Types.ObjectId, ref: "Vehicle" },
    user: {
        type: Schema.Types.ObjectId, ref: "User"
    },
    rating: {
        type: Number
    },
    message: {
        type: String
    }
}, {
    timestamps: true
});

module.exports = mongoose.model('Review', ReviewSchema);