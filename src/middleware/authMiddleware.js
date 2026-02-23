const jwt = require("jsonwebtoken");
const User = require("../models/User");

async function authenticate(req, res, next) {

    try {

        // 1. Extract Authorization header
        const authHeader = req.headers.authorization;

        if (!authHeader) {
            return res.status(401).json({
                message: "Authorization header missing"
            });
        }

        // 2. Extract token
        const parts = authHeader.split(" ");

        if (parts.length !== 2 || parts[0] !== "Bearer") {
            return res.status(401).json({
                message: "Invalid Authorization format"
            });
        }

        const token = parts[1];

        // 3. Verify token
        let payload;

        try {

            payload = jwt.verify(
                token,
                process.env.JWT_ACCESS_SECRET
            );

        } catch {
            return res.status(401).json({
                message: "Invalid or expired token"
            });
        }

        // 4. Fetch user
        const user = await User.findById(payload.sub);

        if (!user) {
            return res.status(401).json({
                message: "User no longer exists"
            });
        }

        // 5. auth_version check (CRITICAL)
        if (user.auth_version !== payload.auth_version) {
            return res.status(401).json({
                message: "Token revoked"
            });
        }

        // 6. Attach user
        req.user = {
            id: user._id,
            role: user.role,
            auth_version: user.auth_version
        };

        next();

    }
    catch (error) {

        console.error("Auth middleware error:", error);

        res.status(500).json({
            message: "Internal server error"
        });

    }
}

module.exports = { authenticate };