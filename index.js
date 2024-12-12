require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const cors = require("cors");
const Users = require("./models/Users"); // Ensure path is correct

const app = express();
const port = process.env.PORT || 4000;

// Middleware
app.use(express.json());
app.use(cors());

// Database Connection
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log("Connected to MongoDB"))
    .catch(err => console.error("MongoDB Connection Error:", err));

// API Routes
app.get("/", (req, res) => {
    res.send("Express App is Running");
});

// Signup Route
app.post('/signup', async (req, res) => {
    try {
        const { name, email, password } = req.body;

        // Check if user already exists
        let user = await Users.findOne({ email });
        if (user) {
            return res.status(400).json({ success: false, error: "User with this email already exists." });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create new user
        user = new Users({ name, email, password: hashedPassword, cartData: Array(300).fill(0) });
        await user.save();

        // Generate token
        const token = jwt.sign({ user: { id: user.id } }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.json({ success: true, token });
    } catch (error) {
        res.status(500).json({ success: false, error: "Internal Server Error" });
    }
});

// Login Route
app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Check if user exists
        const user = await Users.findOne({ email });
        if (!user) {
            return res.status(400).json({ success: false, error: "Invalid email or password." });
        }

        // Compare password
        const passCompare = await bcrypt.compare(password, user.password);
        if (!passCompare) {
            return res.status(400).json({ success: false, error: "Invalid email or password." });
        }

        // Generate token
        const token = jwt.sign({ user: { id: user.id } }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.json({ success: true, token });
    } catch (error) {
        res.status(500).json({ success: false, error: "Internal Server Error" });
    }
});

// Middleware for token verification (for protected routes)
const authenticate = (req, res, next) => {
    const token = req.header("Authorization")?.replace("Bearer ", "");
    if (!token) {
        return res.status(401).json({ success: false, error: "Access Denied: No Token Provided" });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded.user;
        next();
    } catch (error) {
        res.status(400).json({ success: false, error: "Invalid Token" });
    }
};

// Example of a protected route
app.get('/protected', authenticate, (req, res) => {
    res.json({ success: true, message: "This is a protected route" });
});

// Start Server
app.listen(port, () => {
    console.log(`Server Running on Port ${port}`);
});
