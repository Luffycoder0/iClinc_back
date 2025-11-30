const Patient = require('../models/patientModel');
const Doctor = require('../models/doctorModel');
const Subscription = require('../models/subscriptionModel');
const AppError = require('../utils/appError');
const catchAsync = require('../utils/catchAsync');

const filterObj = (obj, ...allowedFields) => {
  const newObj = {};
  Object.keys(obj).forEach((el) => {
    if (allowedFields.includes(el)) newObj[el] = obj[el];
  });
  return newObj;
};

// Get all patients
exports.getAllPatients = catchAsync(async (req, res, next) => {
  const patients = await Patient.find().populate(
    'doctors',
    'name specialty email'
  );
  res.status(200).json({
    status: 'success',
    results: patients.length,
    data: { patients }
  });
});

exports.getAllDoctors = catchAsync(async (req, res, next) => {
  if (!req.user || req.user.role !== 'patient') {
    return next(new AppError('Only admins can access this data', 403));
  }

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

// Get current logged-in patient info
exports.getMe = catchAsync(async (req, res, next) => {
  const patient = await Patient.findById(req.user.id).populate(
    'doctors',
    'name email specialty'
  );
  if (!patient) return next(new AppError('Patient not found', 404));

  res.status(200).json({
    status: 'success',
    data: { patient }
  });
});

// Update current patient profile (not password)
exports.updateMe = catchAsync(async (req, res, next) => {
  if (req.body.password || req.body.passwordConfirm) {
    return next(
      new AppError(
        'This route is not for password updates. Please use /updateMyPassword.',
        400
      )
    );
  }

  // Allow basic info + profile info
  const filteredBody = filterObj(
    req.body,
    'name',
    'email',
    'phone',
    'photo',
    'patientDisease',
    'address',
    'dateOfBirth',
    'aboutMe',
    'medicalHistory',
    'allergies',
    'bloodType',
    'emergencyContact',
    'insurance'
  );

  // Validate blood type if provided
  if (filteredBody.bloodType) {
    const validBloodTypes = ['A+', 'A-', 'B+', 'B-', 'AB+', 'AB-', 'O+', 'O-'];
    if (!validBloodTypes.includes(filteredBody.bloodType)) {
      return next(
        new AppError(
          `Invalid blood type. Must be one of: ${validBloodTypes.join(', ')}`,
          400
        )
      );
    }
  }

  const updatedPatient = await Patient.findByIdAndUpdate(
    req.user.id,
    filteredBody,
    {
      new: true,
      runValidators: true
    }
  );

  res.status(200).json({
    status: 'success',
    data: { patient: updatedPatient }
  });
});

// Deactivate own account
exports.deleteMe = catchAsync(async (req, res, next) => {
  await Patient.findByIdAndUpdate(req.user.id, { active: false });

  res.status(204).json({
    status: 'success',
    data: null
  });
});

// Assign doctor to patient (Many-to-Many) - FIXED VERSION
exports.addDoctorToPatient = catchAsync(async (req, res, next) => {
  const { doctorId } = req.body;

  const doctor = await Doctor.findById(doctorId);
  if (!doctor) return next(new AppError('Doctor not found', 404));

  const patient = await Patient.findById(req.user.id);
  if (!patient) return next(new AppError('Patient not found', 404));

  // Prevent duplicates
  if (patient.doctors.includes(doctorId)) {
    return next(new AppError('Doctor already assigned to this patient', 400));
  }

  // Use updateOne to bypass validation
  await Patient.updateOne(
    { _id: req.user.id },
    { $addToSet: { doctors: doctorId } }
  );

  await Doctor.updateOne(
    { _id: doctorId },
    { $addToSet: { patients: patient._id } }
  );

  // Fetch updated patient
  const updatedPatient = await Patient.findById(req.user.id).populate(
    'doctors'
  );

  res.status(200).json({
    status: 'success',
    message: 'Doctor added successfully',
    data: { patient: updatedPatient }
  });
});

// Remove doctor from patient - FIXED VERSION
exports.removeDoctorFromPatient = catchAsync(async (req, res, next) => {
  const { doctorId } = req.body;

  const patient = await Patient.findById(req.user.id);
  const doctor = await Doctor.findById(doctorId);

  if (!doctor || !patient)
    return next(new AppError('Doctor or patient not found', 404));

  // Use updateOne to bypass validation
  await Patient.updateOne(
    { _id: req.user.id },
    { $pull: { doctors: doctorId } }
  );

  await Doctor.updateOne(
    { _id: doctorId },
    { $pull: { patients: patient._id } }
  );

  res.status(200).json({
    status: 'success',
    message: 'Doctor removed successfully'
  });
});

exports.getMyDoctors = catchAsync(async (req, res, next) => {
  const activeSubscriptions = await Subscription.find({
    patient: req.user._id,
    status: 'active',
    currentPeriodEnd: { $gt: Date.now() }
  }).select('doctor');

  // Extract doctor IDs from active subscriptions
  const doctorIds = activeSubscriptions.map((sub) => sub.doctor);

  if (doctorIds.length === 0) {
    return res.status(200).json({
      status: 'success',
      results: 0,
      data: { doctors: [] }
    });
  }

  // Get full doctor details for subscribed doctors
  const doctors = await Doctor.find({
    _id: { $in: doctorIds }
  }).select(
    'fullName clinicName email phone photo specialization specialty active'
  );

  res.status(200).json({
    status: 'success',
    results: doctors.length,
    data: { doctors }
  });
});
