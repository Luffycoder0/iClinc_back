const jwt = require('jsonwebtoken');
const Admin = require('../models/adminModel');
const Doctor = require('../models/doctorModel');
const Patient = require('../models/patientModel');
const catchAsync = require('../utils/catchAsync');
const AppError = require('../utils/appError');

const signToken = (id) =>
  jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN,
  });

const createSendToken = (admin, statusCode, res) => {
  const token = signToken(admin._id);

  admin.password = undefined;

  res.status(statusCode).json({
    status: 'success',
    token,
    data: {
      admin,
    },
  });
};

exports.signup = catchAsync(async (req, res, next) => {
  const newAdmin = await Admin.create({
    fullName: req.body.fullName,
    email: req.body.email,
    password: req.body.password,
    passwordConfirm: req.body.passwordConfirm,
  });

  createSendToken(newAdmin, 201, res);
});

exports.login = catchAsync(async (req, res, next) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return next(new AppError('Please provide email and password!', 400));
  }

  const admin = await Admin.findOne({ email }).select('+password');

  if (!admin || !(await admin.correctPassword(password, admin.password))) {
    return next(new AppError('Incorrect email or password', 401));
  }

  createSendToken(admin, 200, res);
});

// إضافة getAllDoctors و getAllPatients
exports.getAllDoctors = catchAsync(async (req, res, next) => {
  // التحقق إن الـ user admin (افتراضي إنه فيه req.user من middleware زي protect)
  if (!req.user || req.user.role !== 'admin') {
    return next(new AppError('Only admins can access this data', 403));
  }

  const doctors = await Doctor.find().populate(
    'patients',
    'name email phone patientDisease',
  );
  res.status(200).json({
    status: 'success',
    results: doctors.length,
    data: { doctors },
  });
});

exports.getAllPatients = catchAsync(async (req, res, next) => {
  if (!req.user || req.user.role !== 'admin') {
    return next(new AppError('Only admins can access this data', 403));
  }

  const patients = await Patient.find().populate(
    'doctors',
    'name email specialty',
  );
  res.status(200).json({
    status: 'success',
    results: patients.length,
    data: { patients },
  });
});
