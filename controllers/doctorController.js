const Doctor = require('../models/doctorModel');
const Patient = require('../models/patientModel');
const Subscription = require('../models/subscriptionModel');
const AppError = require('../utils/appError');
const catchAsync = require('../utils/catchAsync');

// Filter allowed fields
const filterObj = (obj, ...allowedFields) => {
  const newObj = {};
  Object.keys(obj).forEach((el) => {
    if (allowedFields.includes(el)) newObj[el] = obj[el];
  });
  return newObj;
};

// Get all doctors
exports.getAllDoctors = catchAsync(async (req, res, next) => {
  const doctors = await Doctor.find().populate(
    'patients',
    'name email phone patientDisease'
  );

  res.status(200).json({
    status: 'success',
    results: doctors.length,
    data: { doctors }
  });
});

// Get current doctor
exports.getMe = catchAsync(async (req, res, next) => {
  const doctor = await Doctor.findById(req.user._id).populate({
    path: 'patients',
    select: 'name email phone patientDisease photo'
  });

  if (!doctor) return next(new AppError('Doctor not found', 404));

  res.status(200).json({
    status: 'success',
    data: { doctor }
  });
});

exports.updateMe = catchAsync(async (req, res, next) => {
  if (req.body.password || req.body.passwordConfirm) {
    return next(
      new AppError(
        'This route is not for password updates. Please use /updateMyPassword.',
        400
      )
    );
  }
  // Allowed fields
  const filteredBody = filterObj(
    req.body,
    'fullName',
    'clinicName',
    'email',
    'phone',
    'photo',
    'location',
    'rate',
    'aboutMe',
    'specialities',
    'designation',
    'experience',
    'education'
  );

  // Validate specialities if provided
  if (filteredBody.specialities) {
    const validSpecialities = [
      'Neurology',
      'Cardiology',
      'Dermatology',
      'Pediatrics'
    ];
    if (!validSpecialities.includes(filteredBody.specialities)) {
      return next(
        new AppError(
          `Invalid speciality. Must be one of: ${validSpecialities.join(', ')}`,
          400
        )
      );
    }
  }

  if (filteredBody.location) {
    if (
      filteredBody.location.type !== 'Point' ||
      !Array.isArray(filteredBody.location.coordinates) ||
      filteredBody.location.coordinates.length !== 2
    ) {
      return next(
        new AppError(
          'Invalid location format. Must be { type: "Point", coordinates: [lng, lat] }',
          400
        )
      );
    }
  }

  const doctor = await Doctor.findByIdAndUpdate(req.user._id, filteredBody, {
    new: true,
    runValidators: true,
    context: 'query'
  });

  if (!doctor) {
    return next(new AppError('Doctor not found', 404));
  }

  res.status(200).json({
    status: 'success',
    data: { doctor }
  });
});

// Soft delete doctor
exports.deleteMe = catchAsync(async (req, res, next) => {
  await Doctor.findByIdAndUpdate(req.user._id, { active: false });
  res.status(204).json({ status: 'success', data: null });
});

// Add patient to doctor
exports.addPatientToDoctor = catchAsync(async (req, res, next) => {
  const { patientId } = req.body;

  const doctor = await Doctor.findByIdAndUpdate(
    req.user._id,
    { $addToSet: { patients: patientId } },
    { new: true }
  );

  const patient = await Patient.findByIdAndUpdate(
    patientId,
    { $addToSet: { doctors: req.user._id } },
    { new: true }
  );

  if (!doctor || !patient)
    return next(new AppError('Doctor or Patient not found', 404));

  res.status(200).json({
    status: 'success',
    message: 'Patient added successfully',
    data: { doctor }
  });
});

// Remove patient from doctor
exports.removePatientFromDoctor = catchAsync(async (req, res, next) => {
  const { patientId } = req.body;

  const doctor = await Doctor.findByIdAndUpdate(
    req.user._id,
    { $pull: { patients: patientId } },
    { new: true }
  );

  const patient = await Patient.findByIdAndUpdate(
    patientId,
    { $pull: { doctors: req.user._id } },
    { new: true }
  );

  if (!doctor || !patient)
    return next(new AppError('Doctor or Patient not found', 404));

  res.status(200).json({
    status: 'success',
    message: 'Patient removed successfully'
  });
});

exports.getMyPatients = catchAsync(async (req, res, next) => {
  // Get all active subscriptions for this doctor
  const activeSubscriptions = await Subscription.find({
    doctor: req.user._id,
    status: 'active',
    paymentStatus: 'paid',
    currentPeriodEnd: { $gt: Date.now() }
  }).select('patient');

  // Extract patient IDs from active subscriptions
  const patientIds = activeSubscriptions.map((sub) => sub.patient);

  if (patientIds.length === 0) {
    return res.status(200).json({
      status: 'success',
      results: 0,
      data: { patients: [] }
    });
  }

  // Get full patient details for subscribed patients
  const patients = await Patient.find({
    _id: { $in: patientIds }
  }).select('name email phone photo patientDisease address dateOfBirth active');

  res.status(200).json({
    status: 'success',
    results: patients.length,
    data: { patients }
  });
});
