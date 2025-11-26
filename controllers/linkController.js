const Doctor = require('../models/doctorModel');
const Patient = require('../models/patientModel');
const catchAsync = require('../utils/catchAsync');
const AppError = require('../utils/appError');

// Many to Many
exports.linkDoctorPatient = catchAsync(async (req, res, next) => {
  const { doctorId, patientId } = req.body;

  const doctor = await Doctor.findById(doctorId);
  const patient = await Patient.findById(patientId);

  if (!doctor || !patient) {
    return next(new AppError('Doctor or Patient not found', 404));
  }

  if (!doctor.patients.includes(patientId)) doctor.patients.push(patientId);
  if (!patient.doctors.includes(doctorId)) patient.doctors.push(doctorId);

  await doctor.save();
  await patient.save();

  res.status(200).json({
    status: 'success',
    message: 'Doctor and Patient linked successfully!'
  });
});

// Get all patients of a each doctor
exports.getDoctorPatients = catchAsync(async (req, res, next) => {
  const doctor = await Doctor.findById(req.params.doctorId).populate(
    'patients'
  );
  if (!doctor) return next(new AppError('Doctor not found', 404));

  res.status(200).json({
    status: 'success',
    data: {
      patients: doctor.patients
    }
  });
});

// Get all doctors of a each patient
exports.getPatientDoctors = catchAsync(async (req, res, next) => {
  const patient = await Patient.findById(req.params.patientId).populate(
    'doctors'
  );
  if (!patient) return next(new AppError('Patient not found', 404));

  res.status(200).json({
    status: 'success',
    data: {
      doctors: patient.doctors
    }
  });
});
