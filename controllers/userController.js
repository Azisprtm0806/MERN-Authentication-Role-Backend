const asyncHandler = require("express-async-handler");
const User = require("../models/userModel");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { generateToken, hashToken } = require("../utils");
const parser = require("ua-parser-js");
const sendEmail = require("../utils/sendMail");
const Token = require("../models/tokenModel");
const crypto = require("crypto");
const Cryptr = require("cryptr");
const { OAuth2Client } = require("google-auth-library");

const cryptr = new Cryptr(process.env.CRYPTR_KEY);
const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

exports.registerUser = asyncHandler(async (req, res) => {
  const { name, email, password } = req.body;

  // Validation
  if (!name || !email || !password) {
    res.status(400);
    throw new Error("Pleas fill in all the required fields.");
  }

  if (password.length < 6) {
    res.status(400);
    throw new Error("Password must be up to 6 characters.");
  }

  // Check if user exists
  const userExists = await User.findOne({ email });
  if (userExists) {
    res.status(400);
    throw new Error("Email already in use.");
  }

  // Get UserAgent
  const ua = parser(req.headers["user-agent"]);
  const userAgent = [ua.ua];

  // create new user
  const user = await User.create({
    name,
    email,
    password,
    userAgent,
  });

  // Generate Token
  const token = generateToken(user._id);

  // Send HTTP-only Cookie
  res.cookie("token", token, {
    path: "/",
    httpOnly: true,
    expires: new Date(Date.now() + 1000 * 86400), // 1 day
    sameSite: "none",
    secure: true,
  });

  if (user) {
    const { _id, name, email, phone, bio, photo, role, isVerified } = user;

    res.status(201).json({
      _id,
      name,
      email,
      phone,
      bio,
      photo,
      role,
      isVerified,
      token,
    });
  } else {
    res.status(400);
    throw new Error("Invalid user data");
  }
});

exports.loginUser = asyncHandler(async (req, res) => {
  const { email, password } = req.body;

  // Validate
  if (!email || !password) {
    res.status(400);
    throw new Error("Pleas add email and password.");
  }

  const user = await User.findOne({ email });

  if (!user) {
    res.status(404);
    throw new Error("User not found, please signup.");
  }

  const passwordIsCorrect = await bcrypt.compare(password, user.password);

  if (!passwordIsCorrect) {
    res.status(400);
    throw new Error("Invalid password.");
  }

  /* ================= generate token before login and save to DB ========================== */
  /* ================= (JIKA BEDA DEVICE ATAU BROWSER UNTUK LOGIN) ========================== */
  // Trigger 2FA for unknow UserAgent
  const ua = parser(req.headers["user-agent"]);
  const thisUserAgent = ua.ua;

  const allowedAgent = user.userAgent.includes(thisUserAgent);

  if (!allowedAgent) {
    // Generate 6 digit code
    const loginCode = Math.floor(100000 + Math.random() * 900000);
    console.log(loginCode);

    // Encrypt login code before saving to DB
    const encryptedLoginCode = cryptr.encrypt(loginCode.toString());

    // Delete token if it exists in DB
    let userToken = await Token.findOne({ userId: user._id });
    if (userToken) {
      await userToken.deleteOne();
    }

    // save token to DB
    await new Token({
      userId: user._id,
      loginToken: encryptedLoginCode,
      createdAt: Date.now(),
      expiresAt: Date.now() + 30 * (60 * 1000), // 60 mins
    }).save();

    res.status(400);
    throw new Error("New Browser or device detected.");
  }

  /* === END (lanjutan ada di contoller sendLoginCode untuk kirim kode ke email) ==== */

  // Generate token
  const token = generateToken(user._id);

  if (user && passwordIsCorrect) {
    // Send HTTP-only Cookie
    res.cookie("token", token, {
      path: "/",
      httpOnly: true,
      expires: new Date(Date.now() + 1000 * 86400), // 1 day
      sameSite: "none",
      secure: true,
    });

    const { _id, name, email, phone, bio, photo, role, isVerified } = user;
    res.status(200).json({
      _id,
      name,
      email,
      phone,
      bio,
      photo,
      role,
      isVerified,
      token,
    });
  } else {
    res.status(500);
    throw new Error("Somthing went wrong, Pleas try again.");
  }
});

exports.sendLoginCode = asyncHandler(async (req, res) => {
  const { email } = req.params;

  const user = await User.findOne({ email });

  if (!user) {
    res.status(404);
    throw new Error("User not found");
  }

  // Find Login Code in DB
  let userToken = await Token.findOne({
    userId: user._id,
    expiresAt: { $gt: Date.now() },
  });

  if (!userToken) {
    res.status(404);
    throw new Error("Invalid or expired token, please login again.");
  }

  const loginCode = userToken.loginToken;
  const decryptedLoginCode = cryptr.decrypt(loginCode.toString());

  // Send login code to email
  const subject = "Login Access Code";
  const send_to = email;
  const send_from = process.env.EMAIL_USER;
  const reply_to = "noreply@azisprtm.com";
  const template = "loginCode";
  const name = user.name;
  const link = decryptedLoginCode;

  try {
    await sendEmail(
      subject,
      send_to,
      send_from,
      reply_to,
      template,
      name,
      link
    );

    res.status(200).json({ message: `Access code sent to ${email}` });
  } catch (error) {
    res.status(500);
    throw new Error("Email not send, please try again.");
  }
});

exports.loginWithCode = asyncHandler(async (req, res) => {
  const { email } = req.params;
  const { loginCode } = req.body;

  // find user
  const user = await User.findOne({ email });

  if (!user) {
    res.status(404);
    throw new Error("User not found.");
  }

  // Find user login token
  const userToken = await Token.findOne({
    userId: user.id,
    expiresAt: { $gt: Date.now() },
  });

  if (!userToken) {
    res.status(404);
    throw new Error("Invalid or Expired Token, Please login again.");
  }

  const decryptedLoginCode = cryptr.decrypt(userToken.loginToken);

  if (loginCode !== decryptedLoginCode) {
    res.status(400);
    throw new Error("Incorrect login code, Please try again.");
  } else {
    // Register userAgent
    const ua = parser(req.headers["user-agent"]);
    const thisUserAgent = ua.ua;

    user.userAgent.push(thisUserAgent);
    await user.save();

    // Generate Token
    const token = generateToken(user._id);

    // Send HTTP-only Cookie
    res.cookie("token", token, {
      path: "/",
      httpOnly: true,
      expires: new Date(Date.now() + 1000 * 86400), // 1 day
      sameSite: "none",
      secure: true,
    });

    const { _id, name, email, phone, bio, photo, role, isVerified } = user;

    res.status(200).json({
      _id,
      name,
      email,
      phone,
      bio,
      photo,
      role,
      isVerified,
      token,
    });
  }
});

exports.logoutUser = asyncHandler(async (req, res) => {
  res.cookie("token", "", {
    path: "/",
    httpOnly: true,
    expires: new Date(0), // 1 day
    sameSite: "none",
    secure: true,
  });
  return res.status(200).json({ message: "Logout successful" });
});

exports.getUser = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user._id);
  if (user) {
    const { _id, name, email, phone, bio, photo, role, isVerified } = user;
    res.status(200).json({
      _id,
      name,
      email,
      phone,
      bio,
      photo,
      role,
      isVerified,
    });
  } else {
    res.status(404);
    throw new Error("User not found.");
  }
});

exports.updateUser = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user._id);

  if (user) {
    const { name, email, phone, bio, photo, role, isVerified } = user;

    user.email = email;
    user.name = req.body.name || name;
    user.phone = req.body.phone || phone;
    user.bio = req.body.bio || bio;
    user.photo = req.body.photo || photo;

    const updatedUser = await user.save();

    res.status(200).json({
      _id: updatedUser._id,
      name: updatedUser.name,
      email: updatedUser.email,
      phone: updatedUser.phone,
      bio: updatedUser.bio,
      photo: updatedUser.photo,
      role: updatedUser.role,
      isVerified: updatedUser.isVerified,
    });
  } else {
    res.status(404);
    throw new Error("User not found.");
  }
});

exports.deleteUser = asyncHandler(async (req, res) => {
  const user = User.findById(req.params.id);

  if (!user) {
    res.status(404);
    throw new Error("User not found.");
  }

  await user.deleteOne();
  res.status(200).json({ message: "User deleted successfully." });
});

exports.getUsers = asyncHandler(async (req, res) => {
  const users = await User.find().sort("-createdAt").select("-password");
  if (!users) {
    res.status(500);
    throw new Error("Something went wrong.");
  }

  res.status(200).json(users);
});

exports.getLoginStatus = asyncHandler(async (req, res) => {
  const token = req.cookies.token;
  if (!token) {
    return res.json(false);
  }

  // verify token
  const verified = jwt.verify(token, process.env.JWT_SECRET);

  if (verified) {
    return res.json(true);
  }
  return res.json(false);
});

exports.upgradeUser = asyncHandler(async (req, res) => {
  const { role, id } = req.body;

  const user = await User.findById(id);

  if (!user) {
    res.status(404);
    throw new Error("User not found.");
  }

  user.role = role;

  await user.save();

  res.status(200).json({
    message: `User role updated to ${role}`,
  });
});

exports.sendAutomatedEmail = asyncHandler(async (req, res) => {
  const { subject, send_to, reply_to, template, url } = req.body;

  if (!subject || !send_to || !reply_to || !template) {
    res.status(400);
    throw new Error("Missing email parameter.");
  }

  // Get user
  const user = await User.findOne({ email: send_to });

  if (!user) {
    res.status(404);
    throw new Error("User not found.");
  }

  const send_from = process.env.EMAIL_USER;
  const name = user.name;
  const link = `${process.env.FRONTEND_URL}${url}`;

  try {
    await sendEmail(
      subject,
      send_to,
      send_from,
      reply_to,
      template,
      name,
      link
    );

    res.status(200).json({ message: "Email Sent" });
  } catch (error) {
    res.status(500);
    throw new Error("Email not send, please try again.");
  }
});

exports.sendVerificationEmail = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user._id);

  if (!user) {
    res.status(404);
    throw new Error("User not found.");
  }

  if (user.isVerified) {
    res.status(400);
    throw new Error("User already verified.");
  }

  // Delete token if it exists in DB
  let token = await Token.findOne({ userId: user._id });
  if (token) {
    await token.deleteOne();
  }

  // Created verification token and save
  const verificationToken = crypto.randomBytes(32).toString("hex") + user._id;
  console.log(verificationToken);

  // Hash token and save
  const hashedToken = hashToken(verificationToken);
  await new Token({
    userId: user._id,
    verifToken: hashedToken,
    createdAt: Date.now(),
    expiresAt: Date.now() + 30 * (60 * 1000), // 60 mins
  }).save();

  // construct Verification url
  const verificationUrl = `${process.env.FRONTEND_URL}/verify/${verificationToken}`;

  // Send verifitacion email
  const subject = "Verify Your Account - AUTH:A";
  const send_to = user.email;
  const send_from = process.env.EMAIL_USER;
  const reply_to = "noreply@azisprtm.com";
  const template = "verifyEMail";
  const name = user.name;
  const link = verificationUrl;

  try {
    await sendEmail(
      subject,
      send_to,
      send_from,
      reply_to,
      template,
      name,
      link
    );

    res.status(200).json({ message: "Verification Email Sent" });
  } catch (error) {
    res.status(500);
    throw new Error("Email not send, please try again.");
  }
});

exports.verifyUser = asyncHandler(async (req, res) => {
  const { verificationToken } = req.params;

  const hashedToken = hashToken(verificationToken);

  const userToken = await Token.findOne({
    verifToken: hashedToken,
    expiresAt: { $gt: Date.now() },
  });

  if (!userToken) {
    res.status(404);
    throw new Error("Invalid or expired token.");
  }

  // Find User
  const user = await User.findOne({ _id: userToken.userId });

  if (user.isVerified) {
    res.status(400);
    throw new Error("User is already verified.");
  }

  // Now verify user
  user.isVerified = true;
  await user.save();
  res.status(200).json({ message: "Account Verification successfully" });
});

exports.forgotPassword = asyncHandler(async (req, res) => {
  const { email } = req.body;

  const user = await User.findOne({ email });

  if (!user) {
    res.status(404);
    throw new Error("No user with this email.");
  }

  // Delete token if it exists in DB
  let token = await Token.findOne({ userId: user._id });
  if (token) {
    await token.deleteOne();
  }

  // Created verification token and save
  const resetToken = crypto.randomBytes(32).toString("hex") + user._id;
  console.log(resetToken);

  // Hash token and save
  const hashedToken = hashToken(resetToken);
  await new Token({
    userId: user._id,
    resetToken: hashedToken,
    createdAt: Date.now(),
    expiresAt: Date.now() + 30 * (60 * 1000), // 60 mins
  }).save();

  // construct reset url
  const resetUrl = `${process.env.FRONTEND_URL}/resetPassword/${resetToken}`;

  // Send verifitacion email
  const subject = "Password Reset Request - AUTH:A";
  const send_to = user.email;
  const send_from = process.env.EMAIL_USER;
  const reply_to = "noreply@azisprtm.com";
  const template = "forgotPassword";
  const name = user.name;
  const link = resetUrl;

  try {
    await sendEmail(
      subject,
      send_to,
      send_from,
      reply_to,
      template,
      name,
      link
    );

    res.status(200).json({ message: "Password Reset Email Sent" });
  } catch (error) {
    res.status(500);
    throw new Error("Email not send, please try again.");
  }
});

exports.resetPassword = asyncHandler(async (req, res) => {
  const { resetToken } = req.params;
  const { password } = req.body;

  const hashedToken = hashToken(resetToken);

  const userToken = await Token.findOne({
    resetToken: hashedToken,
    expiresAt: { $gt: Date.now() },
  });

  if (!userToken) {
    res.status(404);
    throw new Error("Invalid or expired token.");
  }

  // Find User
  const user = await User.findOne({ _id: userToken.userId });

  // Now Reset Password
  user.password = password;
  await user.save();
  res.status(200).json({ message: "Password Reset Successfull, pleas login." });
});

exports.changePassword = asyncHandler(async (req, res) => {
  const { oldPassword, password } = req.body;
  const user = await User.findById(req.user._id);

  if (!user) {
    res.status(404);
    throw new Error("User not found.");
  }

  if (!oldPassword || !password) {
    res.status(400);
    throw new Error("Please enter old and new password.");
  }

  // Chek if old password is correct
  const passwordIsCorrect = await bcrypt.compare(oldPassword, user.password);

  // save new password
  if (user && passwordIsCorrect) {
    user.password = password;
    await user.save();
    res
      .status(200)
      .json({ message: "Password change successful, please re-login" });
  } else {
    res.status(400);
    throw new Error("Old password is incorrect.");
  }
});

exports.loginWithGoogle = asyncHandler(async (req, res) => {
  const { userToken } = req.body;

  const ticket = await client.verifyIdToken({
    idToken: userToken,
    audience: process.env.GOOGLE_CLIENT_ID,
  });

  const payload = ticket.getPayload();
  // console.log(payload)
  const { name, email, picture, sub } = payload;
  const password = Date.now() + sub;

  // Get UserAgent
  const ua = parser(req.headers["user-agent"]);
  const userAgent = [ua.ua];

  // Check if user exists
  const user = await User.findOne({ email });

  if (!user) {
    // create new user
    const newUser = await User.create({
      name,
      email,
      password,
      photo: picture,
      isVerified: true,
      userAgent,
    });

    if (newUser) {
      // Generate Token
      const token = generateToken(newUser._id);

      // Send HTTP-only Cookie
      res.cookie("token", token, {
        path: "/",
        httpOnly: true,
        expires: new Date(Date.now() + 1000 * 86400), // 1 day
        sameSite: "none",
        secure: true,
      });

      const { _id, name, email, phone, bio, photo, role, isVerified } = newUser;

      res.status(201).json({
        _id,
        name,
        email,
        phone,
        bio,
        photo,
        role,
        isVerified,
        token,
      });
    }
  }

  // User already exists, login
  if (user) {
    // Generate Token
    const token = generateToken(user._id);

    // Send HTTP-only Cookie
    res.cookie("token", token, {
      path: "/",
      httpOnly: true,
      expires: new Date(Date.now() + 1000 * 86400), // 1 day
      sameSite: "none",
      secure: true,
    });

    const { _id, name, email, phone, bio, photo, role, isVerified } = user;

    res.status(201).json({
      _id,
      name,
      email,
      phone,
      bio,
      photo,
      role,
      isVerified,
      token,
    });
  }
});
