const express = require("express");
const { getTripsByCategory, addTrip } = require("../controllers/tripController");
const upload = require("../middlewares/multer");
const router = express.Router();

// GET API
router.get("/rides/:category", getTripsByCategory);

// POST API
router.post("/rides/details", upload.array("images", 4), addTrip);

module.exports = router;
