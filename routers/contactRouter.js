const express = require('express');
const router = express.Router();
const contactController = require('../controllers/contactController');


// Define the POST route for contact form
router.post('/contact', (req, res) => {
  const { name, email, message, agree } = req.body;

  if (!name || !email || !message || !agree) {
    return res.status(400).json({ error: 'All fields are required.' });
  }

  // Handle the data (e.g., save to database, send email, etc.)
  console.log('Received contact form submission:', req.body);

  res.status(200).json({ message: 'Your message has been received.' });
});

module.exports = router;
