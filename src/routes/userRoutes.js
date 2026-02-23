const express = require("express");
const { authenticate } = require("../middleware/authMiddleware");
const authorize = require("../middleware/authorize");
const router = express.Router();

router.get("/profile", authenticate, (req, res) => {

    res.json({
        id: req.user.id,
        role: req.user.role,
        auth_version: req.user.auth_version
    });

});


// RBAC test route
router.get(
    "/admin",
    authenticate,
    authorize("admin"),
    (req, res)=>{
        res.json({
            message: "Admin access granted"
        });
    }
)

module.exports = router;