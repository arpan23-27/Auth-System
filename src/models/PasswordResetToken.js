const mongoose = require("mongoose");

const passwordResetTokenSchema = new mongoose.Schema({
    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
        required:true,
        index: true
    },

    token_hash:{
        type: String,
        required: true,
        unique: true,
        index: true
    },

    expires_at:{
        type: Date,
        required: true,
        index: true
    }
},{
timestamps: true

})

module.exports = mongoose.model(
    "PasswordResetToken",
    passwordResetTokenSchema
);