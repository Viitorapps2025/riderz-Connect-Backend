
const Contact = require("../models/contact"); // Import the Contact model



exports. contact= async (req, res) => {
  const { name, email, message, agree } = req.body;

  if (!name || !email || !message || !agree) {
    return res.status(400).json({ error: "All fields are required." });
  }

  try {
    // Create a new contact form submission
    const newContact = new Contact({
      name,
      email,
      message,
      agree,
    });

    // Save the submission to the database
    await newContact.save();

    // Respond with a success message
    res.status(200).json({ message: "Your message has been received." });
  } catch (error) {
    console.error("Error saving contact form:", error);
    res.status(500).json({ error: "There was an error processing your request." });
  }
};

