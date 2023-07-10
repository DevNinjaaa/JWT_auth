import express from "express";
import pkg from "jsonwebtoken";
const { verify, sign } = pkg;
const { createHmac } = await import("node:crypto");

import dotenv from "dotenv";
dotenv.config();

let counter = 1;
let database = [];

function isUserExist(email) {
  const user = database.find((item) => item.email === email);
  if (user) return true;
  else return false;
}

function createNewAccount(email, password) {
  let NewPass = hashPassword(password);
  database.push({ id: counter, password: NewPass, email });
  ++counter;
}

function hashPassword(password) {
  const secret = "MYSECRETKEY";
  const hash = createHmac("sha256", secret).update(password).digest("hex");
  return hash;
}

function compareHashedPassword(email, password) {
  const user = database.find((item) => item.email === email);
  if (!user) return false;

  let hashUser = user.password;
  let comparePass = hashPassword(password);

  if (hashUser === comparePass) {
    return true;
  } else {
    return false;
  }
}

const app = express();

// Middleware to parse JSON bodies
app.use(express.json());

// JWT Secret Key

const jwtSecret = process.env.JWT_SECRET_KEY;
const tokenHeaderKey = process.env.TOKEN_HEADER_KEY;

// Route to create a new account
app.post("/signup", (req, res) => {
  const { email, password } = req.body;

  // Check if user already exists
  if (isUserExist(email)) {
    return res.status(400).json({ message: "User already exists" });
  }

  // Create new account
  createNewAccount(email, password);
  res.json({ message: "Account created successfully" });
});

// Route to login and generate JWT token
app.post("/login", (req, res) => {
  const { email, password } = req.body;

  // Check if user exists and password is correct
  if (!compareHashedPassword(email, password)) {
    return res.status(401).json({ message: "Invalid email or password" });
  }

  // Generate JWT token
  const token = sign({ email }, jwtSecret, { expiresIn: "1h" });

  res.json({ token });
});

// Protected route that requires JWT authentication
app.get("/protected", (req, res) => {
  const token = req.headers.authorization;

  if (!token) {
    return res.status(401).json({ message: "No token provided" });
  }

  try {
    // Verify JWT token
    const decoded = verify(token, jwtSecret);
    const { email } = decoded;

    // Check if user exists
    if (!isUserExist(email)) {
      return res.status(401).json({ message: "User not found" });
    }

    res.json({ message: "Protected data accessed successfully" });
  } catch (err) {
    return res.status(401).json({ message: "Invalid token" });
  }
});
// Protected route that requires JWT authentication
app.get("/protected", (req, res) => {
  const token = req.headers[tokenHeaderKey.toLowerCase()];

  if (!token) {
    return res.status(401).json({ message: "No token provided" });
  }

  try {
    // Verify JWT token
    const decoded = verify(token, jwtSecret);
    const { email } = decoded;

    // Check if user exists
    if (!isUserExist(email)) {
      return res.status(401).json({ message: "User not found" });
    }

    res.json({ message: "Protected data accessed successfully" });
  } catch (err) {
    return res.status(401).json({ message: "Invalid token" });
  }
});

app.listen(4000, () => {
  console.log("listening on port 4000");
});
