const mongoose = require("mongoose");

const tripSchema = new mongoose.Schema({
  category: {
    type: String,
    required: true,
    enum: ["Breakfast", "Workshop", "Expenditure", "Adventure"], // Restrict to valid categories
  },
  id: { type: Number, required: true },
  title: { type: String, required: true },
  date: {
    type: Date,
    required: true,
  },
  price: { type: Number, required: true },
  discount: { type: String },
  images: { type: [String], required: true },
  location: { type: String, required: true },
  rating: { type: Number, required: true },
  features: { type: [String], required: true },
  overviewpic: { type: String, required: true },
  overview: { type: String, required: true },
  highlights: { type: [String], required: true },
  itinerary: [
    {
      day: { type: Number, required: true },
      title: { type: String, required: true },
      description: { type: [String], required: true },
    },
  ],
  stay_options: { type: [String], required: true },
  starting_point: { type: String, required: true },
  ending_point: { type: String, required: true },
  trip_details_pdf: { type: String },
  trip_advisory_pdf: { type: String },
}, { timestamps: true }); // Add timestamps for createdAt and updatedAt

module.exports = mongoose.model("Trip", tripSchema);
