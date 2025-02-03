const mongoose = require('mongoose');


const contactSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true },
  message: { type: String, required: true },
  agree: { type: Boolean, required: true },
  createdAt: { type: Date, default: Date.now },
});

// Create a model based on the schema
const Contact = mongoose.model('Contact', contactSchema);

module.exports = Contact;
