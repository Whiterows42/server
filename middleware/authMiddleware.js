const jwt = require("jsonwebtoken");

const authMiddleware = (req, res, next) => {
  console.log("Cookies: ", req.cookies); // Log the cookies to debug

  const token = req.cookies.token;

  if (!token) {
    return res
      .status(401)
      .json({ success: false, message: "Access denied. No token provided." });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (ex) {
    res.status(400).json({ success: false, message: "Invalid token" });
  }
};

module.exports = authMiddleware;
