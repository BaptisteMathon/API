const setRateLimit = require('express-rate-limit');
const User = require('../models/user');

const adminRateLimiter = setRateLimit({
    windowMs: 60 * 1000, // 1 minute
    message: "Maximum 10 requetes par minute pour l'admin.",
    headers: true,
});

const userRateLimiter = setRateLimit({
    windowMs: 60 * 1000, // 1 minute
    max: 5, 
    message: "Maximum 5 requetes par minute pour l'utilisateur.",
    headers: true,
});

const rateLimitMiddleware = async (req, res, next) => {
    try {
        const user = await User.findById(req.userId);

        if (!user) {
            return res.status(404).json("User not found");
        }

        if (user.admin) {
            return adminRateLimiter(req, res, next);
        } else {
            return userRateLimiter(req, res, next); 
        }
    } catch (error) {
        return res.status(500).json("Erreur serveur");
    }
};

module.exports = rateLimitMiddleware;
