const express = require("express");
const { authenticate } = require("../middleware/authMiddleware");

const router = express.Router();

router.get("/profile", authenticate, (req, res) => {

    res.json({
        id: req.user.id,
        role: req.user.role,
        auth_version: req.user.auth_version
    });

});

module.exports = router;