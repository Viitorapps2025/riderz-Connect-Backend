const Trip = require("../models/trip");
const  upload = require("../middlewares/multer");

// Get all programs by category
const getTripsByCategory = async (req, res) => {
  const { category } = req.params;
  try {
    const trips = await Trip.find({ category });
    res.status(200).json({ [category]: trips });
  } catch (err) {
    res.status(500).json({ error: "Error fetching trips", details: err.message });
  }
};




const addTrip = async (req, res) => {
    try {
      const { category, data } = req.body;
  
      // Validate category
      if (!["Breakfast", "Workshop", "Expenditure", "Adventure"].includes(category)) {
        return res.status(400).json({ error: "Invalid category" });
      }
  
      // Check if images are uploaded
      if (!req.files || req.files.length === 0) {
        return res.status(400).json({ error: "At least one image is required" });
      }
  
      // Add image paths to the data
      const imagePaths = req.files.map(file => `/uploads/${file.filename}`);
      const tripData = JSON.parse(data); // Parse the data if it's a JSON string
      const trip = new Trip({
        category,
        ...tripData,
        images: [...imagePaths, ...(tripData.images || [])], // Add uploaded images to images array
      });
  
      // Save the trip data to the database
      await trip.save();
      res.status(201).json({ message: "Program added successfully", trip });
    } catch (err) {
      res.status(500).json({ error: "Error saving program", details: err.message });
    }
  };
  
module.exports = {
  getTripsByCategory,
  addTrip,
};
