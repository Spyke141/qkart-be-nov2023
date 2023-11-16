//auth.js
const passport = require("passport");
const jwt = require("jsonwebtoken");
const httpStatus = require("http-status");
const ApiError = require("../utils/ApiError");

const verifyCallback = (req, resolve, reject) => async (err, user, info) => {
  if (err || info || !user) {
    return reject(new ApiError(httpStatus.UNAUTHORIZED, "Please authenticate"));
  }

  const accessToken = req.header('Authorization')?.replace('Bearer ', ''); // Get the token from the header
  if (!accessToken) {
    return reject(new ApiError(httpStatus.UNAUTHORIZED, "Access token not found in header"));
  }

  try {
    const decoded = jwt.verify(accessToken, process.env.JWT_SECRET); // Verify the token
    if (decoded.type !== 'access') {
      return reject(new ApiError(httpStatus.UNAUTHORIZED, "Token is not an access token"));
    }
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return reject(new ApiError(httpStatus.UNAUTHORIZED, "Token expired"));
    }
    return reject(new ApiError(httpStatus.UNAUTHORIZED, "Invalid token"));
  }

  req.user = user;
  resolve();
};

const auth = () => async (req, res, next) => {
  return new Promise((resolve, reject) => {
    passport.authenticate(
      "jwt",
      { session: false },
      verifyCallback(req, resolve, reject)
    )(req, res, next);
  })
    .then(() => next())
    .catch((err) => next(err)); // Pass the error to the next middleware
};

module.exports = auth;
