const express = require("express");
const {
  login,
  register,
  checkUser,
  deleteAllUsers,
  verifyOtp,
  deleteAllOtps,
  getUserDetailsByEmail, // Add this line
} = require("../controllers/authController");
const { getUserData } = require("../controllers/userController");
const authMiddleware = require("../middleware/authMiddleware");

const router = express.Router();

router.post("/login", login);
router.post("/register", register);
router.post("/check-user", checkUser);
router.post("/verify-otp", verifyOtp);
// Apply the authMiddleware for protecting routes that require authentication
router.delete("/delete-all-users", authMiddleware, deleteAllUsers);
router.delete("/delete-all-otps", deleteAllOtps); // Add this route
router.get("/userData", authMiddleware, getUserData);
// Define route for retrieving user details by email
router.post("/userdetails",  getUserDetailsByEmail);


module.exports = router;
