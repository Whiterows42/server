const express = require("express");
const { login, register, checkUser } = require("../controllers/authController");

const router = express.Router();

router.post("/login", login);
router.post("/register", register);
router.post("/check-user", checkUser);

module.exports = router;
