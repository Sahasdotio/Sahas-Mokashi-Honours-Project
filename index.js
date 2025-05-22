const express = require('express');
const mongoose = require('mongoose');
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const rateLimit = require("express-rate-limit");

const JWT_SECRET = "HONORS";
const JWT_RESET_SECRET = "SRONOH";

const app = express();
app.use(express.json());

const PORT = 3000;

const pass = "uiek effp sdae jtxr";

const uri ="mongodb+srv://NewUser:abcd1234@cluster0.ium2o.mongodb.net/sample_mflix?retryWrites=true&w=majority&appName=Cluster0" ;

mongoose.connect(uri, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('Connected to MongoDB Atlas!'))
.catch((err) => console.error('Error connecting to MongoDB Atlas:', err));

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: {type: String, required:true},
  verified: { type: Boolean, default: false },
  isLoggedIn: { type: Boolean, default: false}
});

const User = mongoose.model('User', userSchema);

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'tnehal786@gmail.com',
    pass: pass
  }
});

// rate limiter using ip
const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5,
  message: "Too many registration attempts from this IP, please try again after an hour.",
});

//rate limiter using no of failed logins
const failedLogins = new Map();

const loginLimiter = (req, res, next) => {
  const { email } = req.body;
  const attempt = failedLogins.get(email) || { count: 0, lastAttempt: Date.now() };

  if (attempt.count >= 5 && Date.now() - attempt.lastAttempt < 15 * 60 * 1000) {
    return res.status(429).json({ message: "Too many failed login attempts. Try again in 15 minutes." });
  }

  req.failedLoginAttempt = attempt;
  next();
};

app.post('/register',registerLimiter, async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).send('Email is required');

  const existingUser = await User.findOne({ email });
  if (existingUser) return res.status(400).send('User already registered');

  // Generate JWT token
  const token = jwt.sign({ email }, JWT_SECRET, { expiresIn: '15m' }); // valid for 15 mins

  // Send verification email
  const link = `http://localhost:${PORT}/verify-registration?token=${token}`;
  try {
    await transporter.sendMail({
      to: email,
      subject: 'Verify your registration',
      text: `Click this link to verify your registration: ${link}`
    });

    res.send('Verification email sent.');
  } catch (err) {
    console.error('Error sending email:', err);
    res.status(500).send('Failed to send email.');
  }
});

app.post('/verify-registration', async (req, res) => {
  const token = req.query.token;
  const { password } = req.body;

  const hashedPassword = await bcrypt.hash(password,10);

  if (!token) return res.status(400).send('Missing token');

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const email = decoded.email;

    // Check if user already exists
    let user = await User.findOne({ email });

    if (user) {
      if (user.verified) {
        return res.status(400).send('User is already verified');
      }

      user.verified = true;
      await user.save();
      return res.send('Email verified successfully. You can now log in.');
    }

    // If user not found, create and mark as verified
    user = new User({ email,password : hashedPassword, verified: true });
    await user.save();

    res.send('Email verified and user registered successfully.');
  } catch (err) {
    console.error('Verification error:', err.message);
    res.status(400).send('Invalid or expired token');
  }
});

app.post('/login', loginLimiter, async (req, res) => {
  const { email, password } = req.body;

  // 1. Validate input
  if (!email || !password) {
    return res.status(400).send('Email and password are required');
  }

  try {
    // 2. Find user
    const user = await User.findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.password))) {
    // 💥 Add or update the login attempt
    const attempt = req.failedLoginAttempt;
    attempt.count++;
    attempt.lastAttempt = Date.now();
    failedLogins.set(email, attempt); // ✅ This is where insertion happens

    return res.status(401).json({ message: "Invalid credentials" });
  }

  failedLogins.delete(email);

    // 3. Check if verified
    if (!user.verified) {
      return res.status(403).send('Please verify your email before logging in');
    }

    
    //checking of user is logged in
    if (user.isLoggedIn) {
      return res.status(403).json({ message: "User is already logged in on another device." });
    } 
    user.isLoggedIn = true;
    await user.save();

    // 5. Create JWT token
    const token = jwt.sign(
      { userId: user._id, email: user.email },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.header('Authorization', 'Bearer ' + token);

    res.json({ message: 'Login successful', token });
  } catch (err) {
    console.error('Login error:', err.message);
    res.status(500).send('Internal server error');
  }
});

app.get('/protected', (req, res) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; 
   
  console.log("token " , token );
console.log("authheader ", authHeader);

  if (!token) return res.status(401).send('Access denied. No token provided.');

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).send('Invalid or expired token.');
    req.user = user; 
  });
  res.send(`Hello ${req.user.email}, you have accessed a protected route!`);
});

//reset password
app.post("/request-reset", async (req, res) => {
  const { email } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.status(404).json({ message: "Email not found" });

  const token = jwt.sign(
    { id: user._id },
    JWT_RESET_SECRET,
    { expiresIn: "15m" }
  );

  const resetLink = `localhost:3000/reset-password/${token}`;

  await transporter.sendMail({
    from: `"Support" <${process.env.GMAIL_USER}>`,
    to: email,
    subject: "Password Reset",
    html: `<p>Click ${resetLink} here to reset your password. Link expires in 15 minutes.</p>`,
  });

  res.json({ message: "Password reset link sent to email" });
});

app.post("/reset-password/:token", async (req, res) => {
  const { token } = req.params;
  const { newPassword } = req.body;

  try {
    const decoded = jwt.verify(token, JWT_RESET_SECRET);
    const user = await User.findById(decoded.id);
    if (!user) return res.status(400).json({ message: "Invalid token or user" });

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    await user.save();

    res.json({ message: "Password updated successfully" });
  } catch (err) {
    res.status(400).json({ message: "Invalid or expired token" });
  }
});

app.post('/logout', async (req, res) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ message: 'Access denied. No token provided.' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.userId);

    if (!user) return res.status(404).json({ message: 'User not found' });

    user.isLoggedIn = false;
    await user.save();

    res.json({ message: 'Logged out successfully' });
  } catch (err) {
    console.error('Logout error:', err.message);
    res.status(403).json({ message: 'Invalid or expired token.' });
  }
});


app.get('/', (req, res) => {
  res.send('Hello from Express on WSL!');
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});

module.exports = app;