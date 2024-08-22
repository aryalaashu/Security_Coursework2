const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const bookingSchema = new Schema(
  {
    user: { type: Schema.Types.ObjectId, ref: 'User' },
    vehicle: { type: Schema.Types.ObjectId, ref: 'Vehicle' },
    price: { type: Number },
    pickup_date: { type: String },
    drop_date: { type: String },
    status: { type: String, enum: ['booked', 'delivered', 'returned'], default: 'booked' },
    address: { type: String },
    contact: { type: String },
    is_payed: { type: Boolean, default: false },
    is_deleted: { type: Boolean, default: false },
    is_active: { type: Boolean, default: true },
  },
  { timestamps: true },
);
module.exports = mongoose.model('Booking', bookingSchema);
