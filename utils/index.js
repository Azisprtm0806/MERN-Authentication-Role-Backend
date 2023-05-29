const jwt = require("jsonwebtoken");
const crypto = require("crypto");

// generate token
const generateToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: "1d" });
};

// hash token
const hashToken = (token) => {
  return crypto.createHash("sha256").update(token.toString()).digest("hex");
};

module.exports = { generateToken, hashToken };
