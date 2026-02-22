const mongoose = require("mongoose");
const bcrypt = require("bcrypt");

const userSchema = new mongoose.Schema({
    email:{
        type: String,
        required: true,
        unique:true,
        lowercase:true,
        trim:true,
        index:true,
    },

    password_hash:{
        type: String,
        required: true,
    },

    role:{
        type: String,
        enum: ["user", "admin"],
        default:"user",
    },

    is_verified:{
        type: Boolean,
        default: false,
    },

    auth_version:{
        type: Number,
        default:0,
    }
},
    {
        timestamps: true,
    }
)




// Hashing of Password with  Middleware

userSchema.pre("save", async function () {

    if (!this.isModified("password_hash")) {
        return;
    }

    const saltRounds = 12;

    this.password_hash = await bcrypt.hash(this.password_hash, saltRounds);

});

// Password verification
userSchema.methods.verifyPassword = async function (password) {
    return await bcrypt.compare(password, this.password_hash);
};



// Export Model
module.exports = mongoose.model("User", userSchema);