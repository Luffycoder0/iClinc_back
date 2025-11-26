const Subscription = require('../models/subscriptionModel');
const Doctor = require('../models/doctorModel');
const catchAsync = require('../utils/catchAsync');
const AppError = require('../utils/appError');

// Get subscription plans for a specific doctor
exports.getDoctorPlans = catchAsync(async (req, res, next) => {
  const { doctorId } = req.params;

  const doctor = await Doctor.findById(doctorId);
  if (!doctor) {
    return next(new AppError('Doctor not found', 404));
  }

  const plans = [
    {
      name: 'basic',
      price: 10,
      serviceFee: 2,
      total: 12,
      currency: 'USD',
      features: ['Message doctor', 'Book appointments', 'Basic support']
    },
    {
      name: 'standard',
      price: 20,
      serviceFee: 2,
      total: 22,
      currency: 'USD',
      features: ['Everything in Basic', 'Priority booking', '24/7 support']
    },
    {
      name: 'premium',
      price: 30,
      serviceFee: 2,
      total: 32,
      currency: 'USD',
      features: [
        'Everything in Standard',
        'Unlimited consultations',
        'Video calls'
      ]
    }
  ];

  res.status(200).json({
    status: 'success',
    data: { plans, doctor: { id: doctor._id, name: doctor.fullName } }
  });
});

// MOCK PAYMENT
exports.checkout = catchAsync(async (req, res, next) => {
  const { doctorId, plan } = req.body;

  if (!doctorId || !plan) {
    return next(new AppError('Doctor ID and plan are required', 400));
  }

  const doctor = await Doctor.findById(doctorId);
  if (!doctor) {
    return next(new AppError('Doctor not found', 404));
  }

  // Check if patient already has active subscription with this doctor
  const existingSubscription = await Subscription.findOne({
    patient: req.user.id,
    doctor: doctorId,
    status: 'active',
    currentPeriodEnd: { $gt: Date.now() }
  });

  if (existingSubscription) {
    return next(
      new AppError(
        'You already have an active subscription with this doctor',
        400
      )
    );
  }

  // Plan prices
  const planPrices = {
    basic: 10,
    standard: 20,
    premium: 30
  };

  const price = planPrices[plan];
  if (!price) {
    return next(new AppError('Invalid plan selected', 400));
  }

  const serviceFee = 2;
  const totalAmount = price + serviceFee;

  const now = new Date();
  const endDate = new Date(now);
  endDate.setMonth(endDate.getMonth() + 1);

  // Create and activate subscription immediately (MOCK PAYMENT)
  const subscription = await Subscription.create({
    patient: req.user.id,
    doctor: doctorId,
    plan: plan,
    price: price,
    serviceFee: serviceFee,
    totalAmount: totalAmount,
    status: 'active',
    paymentStatus: 'paid',
    currentPeriodStart: now,
    currentPeriodEnd: endDate,
    paymentMethod: 'mock'
  });

  await subscription.populate('doctor', 'fullName email specialty clinicName');

  res.status(201).json({
    status: 'success',
    message:
      'Subscription activated successfully! You can now message and book appointments.',
    data: { subscription }
  });
});

// Check if patient has access to doctor
exports.checkAccess = catchAsync(async (req, res, next) => {
  const { doctorId } = req.params;

  const hasAccess = await Subscription.canAccess(req.user.id, doctorId);

  res.status(200).json({
    status: 'success',
    data: { hasAccess }
  });
});

// Get my active subscriptions
exports.getMySubscriptions = catchAsync(async (req, res, next) => {
  const subscriptions = await Subscription.find({
    patient: req.user.id
  })
    .populate('doctor', 'fullName email specialty photo clinicName')
    .sort({ createdAt: -1 });

  res.status(200).json({
    status: 'success',
    results: subscriptions.length,
    data: { subscriptions }
  });
});

// Get subscription details with specific doctor
exports.getSubscriptionDetails = catchAsync(async (req, res, next) => {
  const { doctorId } = req.params;

  const subscription = await Subscription.findOne({
    patient: req.user.id,
    doctor: doctorId
  })
    .populate('doctor', 'fullName email specialty photo clinicName')
    .sort({ createdAt: -1 });

  res.status(200).json({
    status: 'success',
    data: { subscription }
  });
});

// Cancel subscription
exports.cancelSubscription = catchAsync(async (req, res, next) => {
  const { subscriptionId } = req.params;

  const subscription = await Subscription.findOne({
    _id: subscriptionId,
    patient: req.user.id
  });

  if (!subscription) {
    return next(new AppError('Subscription not found', 404));
  }

  if (subscription.status !== 'active') {
    return next(new AppError('Subscription is not active', 400));
  }

  subscription.status = 'cancelled';
  subscription.cancelAtPeriodEnd = true;
  await subscription.save();

  res.status(200).json({
    status: 'success',
    message: 'Subscription cancelled successfully',
    data: { subscription }
  });
});

// Admin: Get all subscriptions
exports.getAllSubscriptions = catchAsync(async (req, res, next) => {
  const subscriptions = await Subscription.find()
    .populate('patient', 'name email')
    .populate('doctor', 'fullName email specialty')
    .sort({ createdAt: -1 });

  res.status(200).json({
    status: 'success',
    results: subscriptions.length,
    data: { subscriptions }
  });
});
