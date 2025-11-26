const express = require('express');
const appointmentController = require('../controllers/appointmentController');
const authController = require('../controllers/authController');

const router = express.Router();

router.use(authController.protect);

router.post(
  '/book',
  authController.restrictTo('patient'),
  appointmentController.bookAppointment,
);
router.get(
  '/myAppointments',
  authController.restrictTo('patient'),
  appointmentController.getMyAppointments,
);

router.get(
  '/doctorAppointments',
  authController.restrictTo('doctor'),
  appointmentController.getDoctorAppointments,
);
router.patch(
  '/:id/status',
  authController.restrictTo('doctor', 'admin'),
  appointmentController.updateAppointmentStatus,
);

module.exports = router;
