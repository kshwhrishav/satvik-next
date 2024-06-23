require('dotenv').config(); // Load environment variables
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const crypto = require('crypto');
const jwtSecret = crypto.randomBytes(64).toString('hex');

const app = express();
const MONGODB_URI = process.env.MONGODB_URI;
const JWT_SECRET = process.env.JWT_SECRET || jwtSecret;

// Middleware
app.use(express.json());
app.use(cors());

// MongoDB Connection
mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => {
  console.log('MongoDB Connected successfully');
})
.catch(err => {
  console.error('Error connecting to MongoDB:', err.message);
});

// User Schema
const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true }
});

const User = mongoose.model('User', UserSchema);

// Register Route
app.post('/register', async (req, res) => {
  const { username, password } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ username, password: hashedPassword });
    await user.save();
    res.status(201).send('User Registered');
  } catch (err) {
    if (err.code === 11000) {
      // Duplicate key error
      res.status(400).send('Username already exists');
    } else {
      console.error('Error Registering User:', err);
      res.status(500).send('Error Registering User');
    }
  }
});

// Login Route
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  console.log("Logging in user:", username);

  try {
    const user = await User.findOne({ username });

    if (!user) {
      return res.status(400).send('Invalid Username');
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(400).send('Invalid Password');
    }

    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '1h' });

    res.json({ token });
  } catch (err) {
    res.status(500).send('Error logging in user');
  }
});

// Middleware to protect routes
const authMiddleware = (req, res, next) => {
  const token = req.header('Authorization');

  if (!token) {
    return res.status(401).send('Access Denied. No token provided.');
  }

  try {
    const verified = jwt.verify(token, JWT_SECRET);
    req.user = verified;
    next();
  } catch (err) {
    res.status(400).send('Invalid Token');
  }
};

// Protected Route
app.get('/protected', authMiddleware, (req, res) => {
  res.send('This is a protected route');
});

// Start Server
const PORT = process.env.PORT || 3002;
app.listen(PORT, () => {
  console.log(`Server started on port ${PORT}`);
});
