const Subscription = require('../models/subscriptionModel');
const AppError = require('../utils/appError');
const catchAsync = require('../utils/catchAsync');

// Middleware to check if patient has active subscription with doctor
exports.checkSubscription = catchAsync(async (req, res, next) => {
  // Get doctorId from request body or params
  const doctorId =
    req.body.doctorId || req.body.receiverId || req.params.doctorId;

  if (!doctorId) {
    return next(new AppError('Doctor ID is required', 400));
  }

  // Check if patient has active subscription
  const hasAccess = await Subscription.canAccess(req.user.id, doctorId);

  if (!hasAccess) {
    return next(
      new AppError(
        'You need an active subscription to access this doctor. Please subscribe first.',
        403
      )
    );
  }

  next();
});

// Middleware to check subscription for messaging
exports.checkMessageSubscription = catchAsync(async (req, res, next) => {
  const { receiverId } = req.body;
  const senderRole = req.user.role;

  // If sender is doctor, no subscription check needed
  if (senderRole === 'doctor') {
    return next();
  }

  // If sender is patient, check subscription with doctor
  if (!receiverId) {
    return next(new AppError('Receiver ID is required', 400));
  }

  const hasAccess = await Subscription.canAccess(req.user.id, receiverId);

  if (!hasAccess) {
    return next(
      new AppError(
        'You need an active subscription to message this doctor. Please subscribe first.',
        403
      )
    );
  }

  next();
});
