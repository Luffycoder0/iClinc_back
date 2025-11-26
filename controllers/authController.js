const crypto = require('crypto');
const { promisify } = require('util');
const jwt = require('jsonwebtoken');
const User = require('../models/patientModel');
const Doctor = require('../models/doctorModel');
const Admin = require('../models/adminModel');
const catchAsync = require('../utils/catchAsync');
const AppError = require('../utils/appError');
const sendEmail = require('../utils/email');

const signToken = (id) =>
  jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN
  });

const createSendToken = (user, statusCode, res) => {
  const token = signToken(user._id);
  const cookieOptions = {
    expires: new Date(
      Date.now() + process.env.JWT_COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000
    ),
    httpOnly: true
  };
  if (process.env.NODE_ENV === 'production') cookieOptions.secure = true;
  res.cookie('jwt', token, cookieOptions);
  user.password = undefined;
  res.status(statusCode).json({ status: 'success', token, user });
};

exports.signupPatient = catchAsync(async (req, res, next) => {
  // Validate password confirmation
  if (!req.body.password || !req.body.passwordConfirm) {
    return next(
      new AppError('Please provide password and password confirmation', 400)
    );
  }

  if (req.body.password !== req.body.passwordConfirm) {
    return next(new AppError('Passwords do not match!', 400));
  }

  const newPatient = await User.create({
    name: req.body.name,
    phone: req.body.phone,
    email: req.body.email,
    coName: req.body.coName,
    nationalID: req.body.nationalID,
    gender: req.body.gender,
    address: req.body.address,
    password: req.body.password,
    passwordConfirm: req.body.passwordConfirm
  });
  createSendToken(newPatient, 201, res);
});

exports.signupDoctor = catchAsync(async (req, res, next) => {
  // Validate password confirmation
  if (!req.body.password || !req.body.passwordConfirm) {
    return next(
      new AppError('Please provide password and password confirmation', 400)
    );
  }

  if (req.body.password !== req.body.passwordConfirm) {
    return next(new AppError('Passwords do not match!', 400));
  }

  const newDoctor = await Doctor.create({
    fullName: req.body.fullName,
    clinicName: req.body.clinicName,
    licenseID: req.body.licenseID,
    email: req.body.email,
    phone: req.body.phone,
    nationalID: req.body.nationalID,
    gender: req.body.gender,
    address: req.body.address,
    password: req.body.password,
    passwordConfirm: req.body.passwordConfirm
  });
  createSendToken(newDoctor, 201, res);
});

exports.login = catchAsync(async (req, res, next) => {
  const { email, password } = req.body;
  if (!email || !password)
    return next(new AppError('Please provide email and password', 400));

  let user = await Doctor.findOne({ email }).select('+password');
  let userRole = 'doctor';

  if (!user) {
    user = await User.findOne({ email }).select('+password');
    userRole = 'patient';
  }

  if (!user) {
    user = await Admin.findOne({ email }).select('+password');
    userRole = 'admin';
  }

  if (!user || !(await user.correctPassword(password, user.password)))
    return next(new AppError('Incorrect email or password', 401));

  user.role = userRole;

  createSendToken(user, 200, res);
});

exports.protect = catchAsync(async (req, res, next) => {
  let token;
  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith('Bearer')
  ) {
    token = req.headers.authorization.split(' ')[1];
  }
  if (!token) return next(new AppError('You must log in first!', 401));

  const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);

  let currentUser;
  let userRole;

  currentUser = await Doctor.findById(decoded.id);
  if (currentUser) {
    userRole = 'doctor';
  } else {
    currentUser = await User.findById(decoded.id);
    if (currentUser) {
      userRole = 'patient';
    } else {
      currentUser = await Admin.findById(decoded.id);
      if (currentUser) {
        userRole = 'admin';
      }
    }
  }

  if (!currentUser) {
    return next(new AppError('This user no longer exists.', 401));
  }

  if (
    currentUser.changedPasswordAfter &&
    typeof currentUser.changedPasswordAfter === 'function'
  ) {
    if (currentUser.changedPasswordAfter(decoded.iat)) {
      return next(
        new AppError('Password changed recently. Please log in again.', 401)
      );
    }
  }

  req.user = currentUser;
  req.user.role = userRole;

  next();
});

exports.restrictTo =
  (...roles) =>
  (req, res, next) => {
    if (!roles.includes(req.user.role))
      return next(new AppError('You do not have permission!', 403));
    next();
  };

exports.forgotPassword = catchAsync(async (req, res, next) => {
  const user = await User.findOne({ email: req.body.email });
  if (!user) return next(new AppError('No user found with that email', 404));
  const resetToken = user.createPasswordResetToken();
  await user.save({ validateBeforeSave: false });
  const resetURL = `${req.protocol}://${req.get('host')}/api/v1/users/resetPassword/${resetToken}`;
  try {
    await sendEmail({
      email: user.email,
      subject: 'Your password reset token',
      message: `Reset at: ${resetURL}`
    });
    res
      .status(200)
      .json({ status: 'success', message: 'Token sent to email!' });
  } catch (err) {
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save({ validateBeforeSave: false });
    return next(new AppError('Error sending email, try again later!', 500));
  }
});

exports.resetPassword = catchAsync(async (req, res, next) => {
  // Validate password confirmation
  if (!req.body.password || !req.body.passwordConfirm) {
    return next(
      new AppError('Please provide password and password confirmation', 400)
    );
  }

  if (req.body.password !== req.body.passwordConfirm) {
    return next(new AppError('Passwords do not match!', 400));
  }

  const hashedToken = crypto
    .createHash('sha256')
    .update(req.params.token)
    .digest('hex');
  const user = await User.findOne({
    passwordResetToken: hashedToken,
    passwordResetExpires: { $gt: Date.now() }
  });
  if (!user) return next(new AppError('Token invalid or expired', 400));
  user.password = req.body.password;
  user.passwordConfirm = req.body.passwordConfirm;
  user.passwordResetToken = undefined;
  user.passwordResetExpires = undefined;
  await user.save();
  createSendToken(user, 200, res);
});

exports.updatePassword = catchAsync(async (req, res, next) => {
  const { passwordCurrent, password, passwordConfirm } = req.body;

  // Validate new password confirmation
  if (!password || !passwordConfirm) {
    return next(
      new AppError('Please provide new password and password confirmation', 400)
    );
  }

  if (password !== passwordConfirm) {
    return next(new AppError('Passwords do not match!', 400));
  }

  let user;
  if (req.user.role === 'doctor') {
    user = await Doctor.findById(req.user._id).select('+password');
  } else if (req.user.role === 'admin') {
    user = await Admin.findById(req.user._id).select('+password');
  } else {
    user = await User.findById(req.user._id).select('+password');
  }

  if (!user) return next(new AppError('User not found.', 404));

  if (!(await user.correctPassword(passwordCurrent, user.password))) {
    return next(new AppError('Current password is wrong!', 401));
  }

  user.password = password;
  user.passwordConfirm = passwordConfirm;
  user.passwordChangedAt = Date.now() - 1000;
  await user.save();

  createSendToken(user, 200, res);
});

exports.logout = (req, res) => {
  res.cookie('jwt', 'loggedout', {
    expires: new Date(Date.now() + 10 * 1000),
    httpOnly: true
  });
  res
    .status(200)
    .json({ status: 'success', message: 'Logged out successfully' });
};
