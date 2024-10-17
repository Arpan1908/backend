const jwt = require('jsonwebtoken');


const JWT_SECRET = process.env.JWT_SECRET; 


const authMiddleware = (req, res, next) => {
  const authHeader = req.headers.authorization;


  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'Authorization token missing or malformed' });
  }


  const token = authHeader.split(' ')[1];

 
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).json({ message: 'Invalid or expired token' });
    }

   
    req.user = decoded;

 
    next();
  });
};

module.exports = authMiddleware;