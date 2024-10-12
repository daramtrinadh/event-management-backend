const express = require("express");
const dotenv = require("dotenv");
const cors = require("cors");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const EventUser = require("./models/EventUser");

dotenv.config();

const app = express();
app.use(cors()); 
app.use(bodyParser.json());

// Signup route
app.post("/event/signup", async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) {
    return res.status(400).json({ error: "All fields are required" });
  }

  try {
    const existingUser = await EventUser.findOne({ email });
    if (existingUser) {
      return res
        .status(409)
        .json({ error: "Email already exists. Please try logging in." });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new EventUser({
      username,
      email,
      password: hashedPassword,
    });
    await newUser.save(); 
    res.status(201).json({ message: "You can log in now" });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Login route
app.post("/event/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: "All fields are required" });
  }

  try {
    const user = await EventUser.findOne({ email });
    if (!user) {
      return res
        .status(401)
        .json({ error: "User not registered. Please sign up." });
    }

    const isPasswordCorrect = await bcrypt.compare(password, user.password);
    if (isPasswordCorrect) {
      const token = jwt.sign(
        { username: user.username, email: user.email },
        process.env.JWT_SECRET,
        { expiresIn: "24h" }
      );
      res.json({ token });
    } else {
      res.status(401).json({ error: "Invalid credentials" });
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// MongoDB connection
mongoose
  .connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => {
    console.log("MongoDB connected");
    app.listen(5000, () => {
      console.log("Server started and running on port 5000");
    });
  })
  .catch((error) => {
    console.log("Error connecting to MongoDB:", error);
  });
