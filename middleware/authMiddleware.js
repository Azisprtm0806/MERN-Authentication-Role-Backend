const asyncHandler = require("express-async-handler");
const User = require("../models/userModel");
const jwt = require("jsonwebtoken");

const protect = asyncHandler(async (req, res, next) => {
  try {
    const { token } = req.cookies;
    if (!token) {
      res.status(401);
      throw new Error("Not Authorized, Pleas Login.");
    }

    // verify token
    const verified = jwt.verify(token, process.env.JWT_SECRET);
    // Get user id from token
    const user = await User.findById(verified.id).select("-password");
    if (!user) {
      res.status(404);
      throw new Error("User not found.");
    }

    if (user.role === "suspended") {
      res.status(400);
      throw new Error("User suspended, pleas contact support!.");
    }

    req.user = user;
    next();
  } catch (error) {
    res.status(401);
    throw new Error("Not Authorized.");
  }
});

const adminOnly = asyncHandler(async (req, res, next) => {
  if (req.user && req.user.role === "admin") {
    next();
  } else {
    res.status(401);
    throw new Error("Not Authorized as an admin.");
  }
});

const authorOnly = asyncHandler(async (req, res, next) => {
  if (req.user.role === "author" || req.user.role === "admin") {
    next();
  } else {
    res.status(401);
    throw new Error("Not Authorized as an author & admin.");
  }
});

const verifiedOnly = asyncHandler(async (req, res, next) => {
  if (req.user.role && req.user.isVerified === true) {
    next();
  } else {
    res.status(401);
    throw new Error("Not Authorized, account not verified.");
  }
});

module.exports = { protect, adminOnly, authorOnly, verifiedOnly };
