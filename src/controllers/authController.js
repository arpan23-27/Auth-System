const User = require("../models/User");
const bcrypt = require("bcrypt");
const RefreshToken  = require("../models/RefreshToken");




const {
    generateAccessToken,
    generateRefreshToken,
    hashToken,
    getRefreshTokenExpiry
} = require("../services/tokenService");


exports.login = async (req, res) =>{
    try{
        const {email, password} = req.body;
        if(!email || !password){
            return res.status(400).json({
                message: "Email and password required"
            });
        }

        const user = await User.findOne({
            email: email.toLowerCase()
        });


        if(!user) {
            return res.status(401).json({
                message:"Invalid credentials"
            });
        }


        const valid = await bcrypt.compare(
            password,
            user.password_hash
        );


        if(!valid){
            return res.status(401).json({
                message:"Invalid credentials"
            });
        }

        const accessToken = generateAccessToken(user);

        const refreshToken = generateRefreshToken();

        const refreshTokenHash = hashToken(refreshToken);

        await RefreshToken.create({
            user: user._id,
            token_hash: refreshTokenHash,
            expires_at: getRefreshTokenExpiry()
        });

        res.cookie("refresh_token", refreshToken,{
            httpOnly: true,
            secure: false,  //dev only
            sameSite: "strict",
            path: "/api/auth/refresh",
            maxAge: 30 * 24 * 60 * 60 * 1000
        });

        res.json({
            accessToken
        });
    }
    catch (error) {
        console.error("Login error:", error);

        res.status(500).json({
            message: "Internal server error"
        });
    }
};


async function signup(req, res){
    try{
      const { email, password } = req.body;

if (typeof email !== "string" || typeof password !== "string") {
    return res.status(400).json({
        error: "Email and password must be strings"
    });
}

       //Normalize Email
      const normalizedEmail = email.toLowerCase().trim();
        // Check if user already exists
        const existingUser = await User.findOne({email: normalizedEmail});

        if(existingUser){
            return res.status(409).json({
                error: "Accounnt already exists"
            });
        }

        // Create new User

        const user = new User({
            email: normalizedEmail,
            password_hash: password
        });

        await user.save();

        return res.status(201).json({
            message:" User created successfully"
        });
    } catch(error){
        console.log("Signup error:", error);

        return res.status(500).json({
            error: "Internal server error"
        });
    }

}

exports.signup = signup;
