const express = require("express");

const router = express.Router();
const authController = require("../controllers/authController");
const {signup, login , refresh, logout, forgotPassword} = require("../controllers/authController");

router.post("/signup", signup);
router.post("/login", login);
router.post("/logout", logout);
router.post("/forgot-password", forgotPassword);
router.post("/reset-password", authController.resetPassword);
module.exports = router;

