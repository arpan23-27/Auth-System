const jwt = require("jsonwebtoken");
const crypto = require("crypto");

const ACCESS_TOKEN_EXPIRY = "15m";
const REFRESH_TOKEN_EXPIRY_DAYS = 30;


// Generate access token (JWT)
function generateAccessToken(user){
    return jwt.sign(
        {
            sub: user._id.toString(),
            role: user.role,
            auth_version: user.auth_version
        },
        process.env.JWT_ACCESS_SECRET,
        {
            expiresIn: ACCESS_TOKEN_EXPIRY
        }
    );
}




// Generate refresh token (opaque random string)
function generateRefreshToken() {
    return crypto.randomBytes(64).toString("hex");
}

// Hash refresh token before storing
function hashToken(token){
    return crypto
           .createHash("sha256")
           .update(token)
           .digest("hex");
}


//  Calculate expiry date
function getRefreshTokenExpiry(){

    const date = new Date();
    date.setDate(date.getDate()  + REFRESH_TOKEN_EXPIRY_DAYS);
    return date;
}

module.exports = {
    generateAccessToken,
    generateRefreshToken,
    hashToken,
    getRefreshTokenExpiry
};

