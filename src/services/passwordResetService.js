const crypto = require("crypto");
const PasswordResetToken = require("../models/PasswordResetToken");

const REFRESH_TOKEN_EXPIRY_MINUTES =  15;

//Generate secure random token
function generateResetToken() {
    return crypto.randomBytes(32).toString("hex");
}

//Hash token before storing
function hashToken(token){

    return crypto
           .createHash("sha256")
           .update(token)
           .digest("hex");
}


// Calculate expiry time
function getResetTokenExpiry(){
    const date = new Date();
    date.setMinutes(
        date.getMinutes() + REFRESH_TOKEN_EXPIRY_MINUTES
    );

    return date;
}


// Create reset token for user
async function createPasswordResetToken(userId){

    const rawToken = generateResetToken();

    const tokenHash = hashToken(rawToken);

    const expiresAt = getResetTokenExpiry();

    await PasswordResetToken.create({
        user: userId,
        token_hash: tokenHash,
        expires_at: expiresAt
    });

    return rawToken;
}


module.exports = {
    createPasswordResetToken, hashToken
};

