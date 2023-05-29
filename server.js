require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const mongoConnect = require("./config/mongoConnect");
const userRoutes = require("./routes/userRoutes");
const errorHandler = require("./middleware/errorMiddleware");

const app = express();

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(bodyParser.json());
app.use(
  cors({
    origin: ["http://localhost:3000", "https://authz-app.vercel.app"],
    credentials: true,
  })
);

// Routes
app.use("/api/users", userRoutes);
app.get("/", (req, res) => {
  res.send("Home Page");
});

// Error Handler
app.use(errorHandler);

const startServer = async () => {
  const PORT = process.env.PORT || 5000;
  try {
    await mongoConnect();
    app.listen(PORT, () => {
      console.log(`Server On Port ${PORT}`);
    });
  } catch (error) {
    console.log(error);
  }
};

startServer();
