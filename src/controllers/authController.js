const User = require("../models/User");

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

module.exports = { signup };