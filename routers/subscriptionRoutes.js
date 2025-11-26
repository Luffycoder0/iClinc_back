const express = require('express');
const subscriptionController = require('../controllers/subscriptionController');
const authController = require('../controllers/authController');

const router = express.Router();

// Protected routes
router.use(authController.protect);

// Patient routes
router.get(
  '/plans/:doctorId',
  authController.restrictTo('patient'),
  subscriptionController.getDoctorPlans
);

// Mock Checkout
router.post(
  '/checkout',
  authController.restrictTo('patient'),
  subscriptionController.checkout
);

router.get(
  '/check-access/:doctorId',
  authController.restrictTo('patient'),
  subscriptionController.checkAccess
);

router.get(
  '/my-subscriptions',
  authController.restrictTo('patient'),
  subscriptionController.getMySubscriptions
);

router.get(
  '/details/:doctorId',
  authController.restrictTo('patient'),
  subscriptionController.getSubscriptionDetails
);

router.patch(
  '/cancel/:subscriptionId',
  authController.restrictTo('patient'),
  subscriptionController.cancelSubscription
);

// Admin routes
router.get(
  '/all',
  authController.restrictTo('admin'),
  subscriptionController.getAllSubscriptions
);

module.exports = router;
