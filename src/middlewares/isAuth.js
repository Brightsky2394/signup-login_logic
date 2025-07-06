const jwt = require('jsonwebtoken');

const isAuthenticated = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        // validate authorization header
        if (!authHeader || !authHeader.startsWith("Bearer")) {
            return res.status(401).json({
                message: "Authentication failed: Authorization header missing"
            })
        }
        const token = authHeader.split(' ')[1];
        // validate token
        if (!token) {
            return res.status(401).json({
                message: "Authentication failed: Token missing"
            })
        }
        // verify token
        const decoded = await jwt.verify(token, process.env.JWT_SECRET);
        if (!decoded) {
            return res.status(401).json({
                message: "Authentication failed: invalid token"
            })
        }
        req.user = decoded;
        next();
    } catch (err) {
        console.error("Authentication error\n", err.message);
        return res.status(401).json({
            message: "Authentication failed: invalid token"
        })
    }
}

module.exports = isAuthenticated;