const mongoose = require("mongoose")
const User = require("./User")

const refreshTokenSchema = new mongoose.Schema({
    user:{
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
        required : true,
        index: true
    },

    token_hash:{
        type: String,
        required: true,
        unique: true
    },
    expires_at :{
        type: Date,
        required: true,
        index: true
    },
    created_at:{
        type: Date,
        default: Date.now
    }
});


module.exports = mongoose.model("RefreshToken", refreshTokenSchema);