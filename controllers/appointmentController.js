const Appointment = require('../models/appointmentModel');
const Doctor = require('../models/doctorModel');
const Patient = require('../models/patientModel');
const Subscription = require('../models/subscriptionModel');
const catchAsync = require('../utils/catchAsync');
const AppError = require('../utils/appError');

// Book appointment after subscription
exports.bookAppointment = catchAsync(async (req, res, next) => {
  const { doctorId, date, time } = req.body;

  const doctor = await Doctor.findById(doctorId);
  if (!doctor) return next(new AppError('Doctor not found', 404));

  const hasAccess = await Subscription.canAccess(req.user.id, doctorId);

  if (!hasAccess) {
    return next(
      new AppError(
        'You need an active subscription to book appointments with this doctor. Please subscribe first.',
        403
      )
    );
  }

  const appointment = await Appointment.create({
    doctor: doctorId,
    patient: req.user.id,
    date,
    time,
    status: 'pending'
  });

  res.status(201).json({
    status: 'success',
    message: 'Appointment booked successfully!',
    data: { appointment }
  });
});

// Get all appointments for a patient
exports.getMyAppointments = catchAsync(async (req, res, next) => {
  const appointments = await Appointment.find({ patient: req.user.id })
    .populate('doctor', 'fullName email specialty')
    .sort({ date: 1 });

  res.status(200).json({
    status: 'success',
    results: appointments.length,
    data: { appointments }
  });
});

// Get all appointments for a doctor
exports.getDoctorAppointments = catchAsync(async (req, res, next) => {
  const appointments = await Appointment.find({ doctor: req.user.id })
    .populate('patient', 'name email phone')
    .sort({ date: 1 });

  res.status(200).json({
    status: 'success',
    results: appointments.length,
    data: { appointments }
  });
});

// Update appointment status
exports.updateAppointmentStatus = catchAsync(async (req, res, next) => {
  const appointment = await Appointment.findByIdAndUpdate(
    req.params.id,
    { status: req.body.status },
    { new: true, runValidators: true }
  );

  if (!appointment) return next(new AppError('Appointment not found', 404));

  res.status(200).json({
    status: 'success',
    message: 'Status updated successfully',
    data: { appointment }
  });
});

// Cancel appointment
exports.cancelAppointment = catchAsync(async (req, res, next) => {
  const appointment = await Appointment.findOne({
    _id: req.params.id,
    patient: req.user.id
  });

  if (!appointment) {
    return next(new AppError('Appointment not found', 404));
  }

  if (appointment.status === 'cancelled') {
    return next(new AppError('Appointment is already cancelled', 400));
  }

  appointment.status = 'cancelled';
  await appointment.save();

  res.status(200).json({
    status: 'success',
    message: 'Appointment cancelled successfully',
    data: { appointment }
  });
});
