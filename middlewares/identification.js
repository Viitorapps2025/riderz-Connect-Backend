const jwt = require('jsonwebtoken');

// exports.identifier = (req, res, next) => {
//     const token = req.cookies.Authorization?.split(' ')[1]; // Extract token from cookie

//     if (!token) {
//         return res.status(401).json({ success: false, message: 'No token provided' });
//     }

//     try {
//         const decoded = jwt.verify(token, process.env.TOKEN_SECRET);
//         req.user = decoded; // Attach user info to the request
//         next(); // Proceed to the next middleware or route handler
//     } catch (error) {
//         return res.status(401).json({ success: false, message: 'Invalid or expired token' });
//     }
// };






exports.identifier = (req, res, next) => {
    try {
        // Retrieve the Authorization header
        const authHeader = req.headers?.authorization;
        console.log('Authorization Header:', authHeader); // Debug log

        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ success: false, message: 'Authorization header missing or malformed' });
        }

        // Extract the token from the Bearer header
        const token = authHeader.split(' ')[1];

        if (!token) {
            return res.status(401).json({ success: false, message: 'Token not found in Authorization header' });
        }

        // Verify the token using the secret key
        const decoded = jwt.verify(token, process.env.TOKEN_SECRET);
        console.log('Decoded Token:', decoded); // Debug log for token content

        // Attach user information to the request object
        req.user = decoded;

        // Proceed to the next middleware or route handler
        next();
    } catch (error) {
        console.error('Token Verification Error:', error.message); // Log error for debugging
        // Handle specific JWT errors if needed
        const errorMessage = 
            error.name === 'TokenExpiredError' ? 'Token has expired' :
            error.name === 'JsonWebTokenError' ? 'Invalid token' :
            'Token verification failed';

        return res.status(401).json({ success: false, message: errorMessage });
    }
};




exports. authenticateToken=(req, res, next)=> {
    const token = req.headers["authorization"]?.split(" ")[1];
    if (token == null) return res.sendStatus(401);
  
    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
      if (err) return res.sendStatus(403);
      req.user = user;
      next();
    });
  }

