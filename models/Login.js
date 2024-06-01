const mongoose = require("mongoose");

const LoginSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      required: true,
      unique: true,
      trim: true,
    },
    firstName: {
      type: String,
      required: true,
      trim: true,
    },
    lastName: {
      type: String,
      required: true,
      trim: true,
    },
    email: {
      type: String,
      required: true,
      unique: true,
      trim: true,
      match: [/.+\@.+\..+/, "Please fill a valid email address"],
    },
    password: {
      type: String,
      required: true,
    },
    emailThreadId: { type: String },
    encryptionKey: {
      type: String,
      required: true, // Optional: if you want to ensure all users have an encryption key
    },
  },
  { timestamps: true }
);

const Login = mongoose.model("Login", LoginSchema);

module.exports = Login;
