const formidable = require('formidable');
const path = require('path');

// Configure the upload settings
const uploadimg = (req, res, next) => {
  const form = new formidable.IncomingForm();
  form.uploadDir = path.join(__dirname, '..', 'uploads');
  form.keepExtensions = true; // Preserve file extensions

  form.parse(req, (err, fields, files) => {
    if (err) {
      return res.status(500).json({ error: 'File upload failed' });
    }

    // Ensure the uploaded file is an image
    if (!files.image || !files.image[0].type.startsWith('image/')) {
      return res.status(400).json({ error: 'Only image files are allowed' });
    }

    req.files = files;
    req.fields = fields;  // Form data
    next();  // Proceed to next middleware
  });
};

module.exports = uploadimg;
