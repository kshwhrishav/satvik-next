require('dotenv').config(); // Load environment variables
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
const MONGODB_URI = process.env.MONGODB_URI;
const JWT_SECRET = process.env.JWT_SECRET;

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

// Login Route with extended expiration
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

    // Issue token with extended expiration (e.g., 7 days)
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '7d' });

    res.json({ token });
  } catch (err) {
    res.status(500).send('Error logging in user');
  }
});

// Refresh Token Route
app.post('/refresh-token', async (req, res) => {
  const token = req.header('Authorization');

  if (!token) {
    return res.status(401).send('Access Denied. No token provided.');
  }

  try {
    const verified = jwt.verify(token, JWT_SECRET);

    // Issue new token with refreshed expiration
    const refreshedToken = jwt.sign({ userId: verified.userId }, JWT_SECRET, { expiresIn: '7d' });

    res.json({ token: refreshedToken });
  } catch (err) {
    res.status(400).send('Invalid Token');
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
// Validate Token Route
  // Validate Token Route
app.post('/api/validate-token', authMiddleware, async (req, res) => {
  try {
    // req.user contains the decoded JWT payload from authMiddleware
    const userId = req.user.userId;

    // Fetch user details from MongoDB based on userId
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // If user is found, respond with user details and success message
    res.status(200).json({ user, message: 'Token is valid' });
  } catch (err) {
    console.error('Error validating token:', err);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});


// Protected Route
app.get('/dashboard', authMiddleware, (req, res) => {
  res.send('This is a protected route');
});

// Start Server
const PORT = process.env.PORT || 3002;
app.listen(PORT, () => {
  console.log(`Server started on port ${PORT}`);
});
