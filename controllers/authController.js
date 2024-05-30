const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
const Login = require("../models/Login");
const Otp = require("../models/Otp");
const transporter = require("../config/nodemailer");

// Utility function to set a secure cookie
function setTokenCookie(res, token) {
  res.cookie("token", token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production", // set to true in production
    maxAge: 3600000, // 1 hour
  });
}

exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res
        .status(400)
        .json({ success: false, message: "Email and password are required" });
    }

    const user = await Login.findOne({ email });

    if (!user) {
      return res
        .status(404)
        .json({ success: false, message: "User not found" });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res
        .status(401)
        .json({ success: false, message: "Invalid password" });
    }

    // Generate OTP
    const otp = crypto.randomInt(100000, 999999).toString();
    const otpExpiration = Date.now() + 10 * 60 * 1000; // OTP valid for 10 minutes

    await Otp.create({ email, otp, expiresAt: otpExpiration });

    // Generate or retrieve email thread ID
    if (!user.emailThreadId) {
      user.emailThreadId = crypto.randomUUID();
      await user.save();
    }

    const threadId = user.emailThreadId;

    // Send OTP to user's email
    const mailOptions = {
      from: process.env.EMAIL,
      to: email,
      subject: "Your OTP Code",
      html: `
        <!DOCTYPE html>
        <html>
        <head>
          <style>
            body {
              font-family: Arial, sans-serif;
            }
            .container {
              width: 100%;
              padding: 20px;
              text-align: center;
              background-color: #f4f4f4;
            }
            .content {
              max-width: 600px;
              margin: auto;
              background-color: #ffffff;
              padding: 20px;
              border-radius: 10px;
              box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
            }
            .logo {
              width: 100px;
              margin-bottom: 20px;
            }
            .otp {
              font-size: 24px;
              font-weight: bold;
              color: #333333;
            }
            .footer {
              margin-top: 20px;
              font-size: 12px;
              color: #999999;
            }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="content">
              <img src="https://akm-img-a-in.tosshub.com/indiatoday/images/story/202011/Screenshot_2020-11-05_at_5.14._1200x768.png?size=690:388" alt="Company Logo" class="logo">
              <h2>Your OTP Code</h2>
              <p class="otp">${otp}</p>
              <p>This OTP code is valid for 10 minutes.</p>
              <div class="footer">
                <p>&copy; 2024 Your Company. All rights reserved.</p>
              </div>
            </div>
          </div>
        </body>
        </html>
      `,
      headers: {
        "Message-ID": `<${threadId}@yourdomain.com>`,
        "In-Reply-To": `<${threadId}@yourdomain.com>`,
        References: `<${threadId}@yourdomain.com>`,
      },
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.error("Error sending OTP email:", error);
        return res
          .status(500)
          .json({ success: false, message: "Error sending OTP email" });
      }
      console.log("OTP email sent:", info.response);
      return res
        .status(200)
        .json({ success: true, message: "OTP sent to email" });
    });
  } catch (err) {
    console.error("Internal server error:", err);
    res.status(500).json({ success: false, error: "Internal Server Error" });
  }
};


exports.verifyOtp = async (req, res) => {
  try {
    const { email, otp } = req.body;

    if (!email || !otp) {
      return res
        .status(400)
        .json({ success: false, message: "Email and OTP are required" });
    }

    const otpRecord = await Otp.findOne({ email, otp });

    if (!otpRecord) {
      return res.status(400).json({ success: false, message: "Invalid OTP" });
    }

    if (otpRecord.expiresAt < Date.now()) {
      return res.status(400).json({ success: false, message: "OTP expired" });
    }

    const user = await Login.findOne({ email });

    if (!user) {
      return res
        .status(400)
        .json({ success: false, message: "User not found" });
    }

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: "1h",
    });

    // Set token in HTTP-only cookie
    setTokenCookie(res, token);

    // Optionally delete the OTP record after use
    await Otp.deleteOne({ email, otp });

    return res.status(200).json({
      success: true,
      message: "User authenticated successfully",
      token,
    });
  } catch (err) {
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
    if (user) {
      return res
        .status(400)
        .json({ success: false, message: "Email already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    user = new Login({
      email,
      password: hashedPassword,
      username,
      firstName,
      lastName,
    });

    await user.save();

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: "1h",
    });

    // Set token in HTTP-only cookie
    setTokenCookie(res, token);

    res.status(201).json({
      success: true,
      message: "User created successfully",
      token,
    });
  } catch (err) {
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
      res.status(200).json({ success: true, message: "User exists" });
    } else {
      res.status(404).json({ success: false, message: "User does not exist" });
    }
  } catch (err) {
    res.status(500).json({ success: false, error: "Internal Server Error" });
  }
};

exports.deleteAllUsers = async (req, res) => {
  try {
    await Login.deleteMany({});
    res
      .status(200)
      .json({ success: true, message: "All users deleted successfully" });
  } catch (err) {
    res.status(500).json({ success: false, error: "Internal Server Error" });
  }
};

exports.deleteAllOtps = async (req, res) => {
  try {
    await Otp.deleteMany({});
    res.status(200).json({ success: true, message: "All OTPs deleted successfully" });
  } catch (err) {
    res.status(500).json({ success: false, error: "Internal Server Error" });
  }
};
