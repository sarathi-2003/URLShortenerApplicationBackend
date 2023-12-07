const User = require('../models/User');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');

const generateToken = (email) => {
    return jwt.sign({ email }, process.env.SECRET_KEY, { expiresIn: '1d' });
  };


  const sendActivationEmail = async (email, activationToken) => {
    try {
      const transporter = nodemailer.createTransport({
        service: 'gmail',
        host: 'smtp.gmail.com',
        port: 587,
        secure: false,
        auth: {
          user: process.env.EMAIL_FROM,
          pass: process.env.EMAIL_PASSWORD,
        },
      });
  
      const mailOptions = {
        from: 'ragavi5901@example.com',
        to: email,
        subject: 'Account Activation',
        html: `<p>Click <a href="http://localhost:5000/api/auth/activate/${activationToken}">here</a> to activate your account.</p>`,
      };
  
      await transporter.sendMail(mailOptions);
    } catch (error) {
      console.error('Error sending activation email:', error);
      // Handle the error, perhaps by sending a response to the client
      throw new Error('Error sending activation email');
    }
  };
  const authController = {
    register: async (req, res) => {
      try {
        const { email, password, firstName, lastName } = req.body;
  
        // Check if the email is already registered
        const existingUser = await User.findOne({ email });
        if (existingUser) {
          return res.status(400).json({ message: 'Email is already registered' });
        }
  
        // Create a new user
        const user = new User({ email, password, firstName, lastName });
        user.activationToken = generateToken(email);
        await user.save();
  
        // Send activation email
        await sendActivationEmail(email, user.activationToken);
  
        res.status(201).json({ message: 'Registration successful. Please check your email for activation.' });
      } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Internal server error' });
      }
    },
    
      activate: async (req, res) => {
        try {
          const { token } = req.params;
    
          // Decode and verify the token
          const decodedToken = jwt.verify(token, process.env.SECRET_KEY);
    
          // Update user's isActive status
          await User.findOneAndUpdate({ email: decodedToken.email }, { $set: { isActive: true } });
    
          // Redirect or send a success message
          res.redirect('your_frontend_activation_success_page_url');
        } catch (error) {
          console.error(error);
          res.status(400).json({ message: 'Invalid or expired activation token' });
        }
      },
    

  login: async (req, res) => {
    try {
      const { email, password } = req.body;

      // Check if the user exists
      const user = await User.findOne({ email });
      if (!user || !await bcrypt.compare(password, user.password)) {
        return res.status(401).json({ message: 'Invalid credentials' });
      }

      // Check if the user is activated
      if (!user.isActive) {
        return res.status(401).json({ message: 'Account not activated' });
      }

      // Generate and send JWT token
      const token = generateToken(user._id);
      res.json({ token });
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: 'Internal server error' });
    }
  },
  forgotPassword: async (req, res) => {
    try {
      const { email } = req.body;

      // Check if the user exists
      const user = await User.findOne({ email });
      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }

      // Generate a password reset token
      const resetToken = generateToken(email);

      // Save the token in the user's document
      user.resetToken = resetToken;
      await user.save();

      // Send the password reset email
      await sendPasswordResetEmail(email, resetToken);

      res.json({ message: 'Password reset email sent. Check your email for instructions.' });
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: 'Internal server error' });
    }
  },
  resetPassword: async (req, res) => {
    try {
      const { token, newPassword } = req.body;

      // Decode and verify the reset token
      const decodedToken = jwt.verify(token, process.env.SECRET_KEY);

      // Find the user associated with the reset token
      const user = await User.findOne({ email: decodedToken.email });

      // Check if the user and token are valid
      if (!user || user.resetToken !== token) {
        return res.status(400).json({ message: 'Invalid or expired reset token' });
      }

      // Hash the new password
      const hashedPassword = await bcrypt.hash(newPassword, 10);

      // Update user's password and deactivate the reset token
      user.password = hashedPassword;
      user.resetToken = undefined;
      await user.save();

      res.json({ message: 'Password reset successful' });
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: 'Internal server error' });
    }
  },
};

module.exports = authController;
