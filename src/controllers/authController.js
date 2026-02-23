const User = require("../models/User");
const bcrypt = require("bcrypt");
const RefreshToken  = require("../models/RefreshToken");




const {
    generateAccessToken,
    generateRefreshToken,
    hashToken,
    getRefreshTokenExpiry
} = require("../services/tokenService");

exports.logout = async (req, res )=>{
    try{
        const refreshToken = req.cookies.refresh_token;
        if(refreshToken){

            const tokenHash = hashToken(refreshToken);

            await RefreshToken.deleteOne({
                token_hash: tokenHash
            });
        }

        res.clearCookie("refresh_token", {
            httpOnly: true,
            secure: false, // true in production
            sameSite: "strict",
            path: "/api/auth/refresh"
        });

        res.json({
            message: "Logged out succesfully"
        });
    }
    catch(error){
        console.log("Logout error:", error);

        res.status(500).json({
            message: "Internal server error"
        });
    }
};
//refresh token validation 
exports.refresh = async (req, res) =>{
    try{
        const refreshToken = req.cookies.refresh_token;
        
        if(!refreshToken){
            return res.status(401).json({
                message:"Refresh token missing"
            });
        }

        const tokenHash = hashToken(refreshToken);

        const storedToken = await RefreshToken.findOne({
            token_hash: tokenHash
        }).populate("user");


        //Step 1.  Reuse Detection
        if(!storedToken){
            return res.status(403).json({
                message: "Invalid refresh token (possible reuse detected)"
            });
        }

        // Step2. Check expiry
        if(storedToken.expires_at  < new Date()) {
            await RefreshToken.deleteOne({ _id: storedToken._id});

            return res.status(403).json({
                message:"Refresh token expired"
            });
        }

        if (!storedToken.user) {
    await RefreshToken.deleteOne({ _id: storedToken._id });

    return res.status(403).json({
        message: "User no longer exists"
    });
}
         // Step.4 Safe to proceed
        const user = storedToken.user;

        //ROTATION -- delte old token
        await RefreshToken.deleteOne({
            _id: storedToken._id
        });

        // generate new tokens

        const newAccessToken = generateAccessToken(user);

        const newRefreshToken = generateRefreshToken();

        const newRefreshTokenHash = hashToken(newRefreshToken);


        await RefreshToken.create({
            user: user._id,
            token_hash: newRefreshTokenHash,
            expires_at: getRefreshTokenExpiry()
        });

        res.cookie("refresh_token", newRefreshToken, {
            httpOnly: true,
            secure: false, //dev only
            sameSite: "strict",
            path: "/api/auth/refresh",
            maxAge: 30 * 24 * 60 * 60 * 1000
        });

        res.json({
            accessToken: newAccessToken
        });
    }

    catch(error){
        console.error("Refresh error:", error);
        res.status(500).json({
            message: "Internal server error"
        });
    }
}

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
