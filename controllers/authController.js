const Login = require("../models/Login");

exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res
        .status(400)
        .json({ success: false, message: "Email and password are required" });
    }

    const user = await Login.findOne({ email });

    if (user) {
      if (password === user.password) {
        console.log("User authenticated successfully");
        return res
          .status(200)
          .json({ success: true, message: "User authenticated successfully" });
      } else {
        console.log("Invalid password");
        return res
          .status(401)
          .json({ success: false, message: "Invalid password" });
      }
    } else {
      console.log("User not found");
      return res
        .status(404)
        .json({ success: false, message: "User not found" });
    }
  } catch (err) {
    console.error("Error during login:", err);
    res.status(500).json({ success: false, error: "Internal Server Error" });
  }
};

exports.register = async (req, res) => {
  try {
    const { email, password, username, firstName, lastName } = req.body;

    if (!email || !password) {
      return res
        .status(400)
        .json({ success: false, message: "Email and password are required" });
    }

    let user = await Login.findOne({ email });
    let pwd = await Login.findOne({ password });
    if (user) {
      return res
        .status(400)
        .json({ success: false, message: "Email already exists" });
    }
    if (pwd) {
      return res
        .status(400)
        .json({ success: false, message: "password already exists" });
    }

    user = new Login({
      email,
      password,
      username,
      firstName,
      lastName,
    });

    await user.save();
    console.log("User created successfully");
    res
      .status(201)
      .json({ success: true, message: "User created successfully" });
  } catch (err) {
    console.error("Error during registration:", err);
    res.status(500).json({ success: false, error: "Internal Server Error" });
  }
};

exports.checkUser = async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res
        .status(400)
        .json({ success: false, message: "Email is required" });
    }

    const user = await Login.findOne({ email });

    if (user) {
      console.log("User exists");
      res.status(200).json({ success: true, message: "User exists" });
    } else {
      console.log("User does not exist");
      res.status(404).json({ success: false, message: "User does not exist" });
    }
  } catch (err) {
    console.error("Error checking user:", err);
    res.status(500).json({ success: false, error: "Internal Server Error" });
  }
};
