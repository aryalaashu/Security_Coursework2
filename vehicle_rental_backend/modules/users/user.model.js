const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const userSchema = new Schema(
    {
        firstname: { type: String, required: true },
        lastname: { type: String, required: true },
        email: { type: String, required: true, unique: true },
        contact: { type: Number },
        address: { type: String },
        password: { type: String, required: true },
        oldPasswords: { type: [String], default: [], validate: [arrayLimit, 'Exceeds the limit of 3'] },
        role: {
            type: [String], default: "user", enum: [
                "user",
                "admin",
                "superadmin"
            ]
        },
        loginAttempt: { type: Number, default: 0 },
        accountLockedUntil: { type: Date, default: null },
        image: { type: String },
        is_deleted: { type: Boolean, default: false },
    },
    { timestamps: true }
);

function arrayLimit(val) {
    return val.length <= 3;
}


module.exports = mongoose.model('User', userSchema);
