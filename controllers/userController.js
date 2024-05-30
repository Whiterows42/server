const Login = require("../models/Login");

exports.getUserData = async (req, res) => {
  try {
    const user = await Login.findById(req.user.id);
    if (!user) {
      return res
        .status(404)
        .json({ success: false, message: "User not found" });
    }
    res.status(200).json({ success: true, data: user });
  } catch (err) {
    console.error("Error fetching user data:", err);
    res.status(500).json({ success: false, message: "Internal Server Error" });
  }
};
