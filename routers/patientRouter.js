const express = require('express');
const patientController = require('../controllers/patientController');
const authController = require('../controllers/authController');

const router = express.Router();

// Public routes
router.post('/signup', authController.signupPatient);
router.post('/login', authController.login);
router.post('/logout', authController.logout);
router.post('/forgotPassword', authController.forgotPassword);
router.post('/verifyResetCode', authController.verifyResetCode);
router.patch('/resetPassword/:token', authController.resetPassword);

// Protected routes
router.use(authController.protect);
router.get('/me', patientController.getMe);
router.patch('/updateMe', patientController.updateMe);
router.delete('/deleteMe', patientController.deleteMe);
router.patch('/updateMyPassword', authController.updatePassword);
router.get('/doctors', patientController.getAllDoctors);
router.get('/myDoctors', patientController.getMyDoctors);
router.post('/addDoctor', patientController.addDoctorToPatient);
router.post('/removeDoctor', patientController.removeDoctorFromPatient);

// Admin only
router.use(authController.restrictTo('admin'));
router.get('/', patientController.getAllPatients);

module.exports = router;
