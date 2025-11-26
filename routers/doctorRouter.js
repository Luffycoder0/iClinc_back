const express = require('express');
const doctorController = require('../controllers/doctorController');
const authController = require('../controllers/authController');
const router = express.Router();

// Public routes (no authentication needed)
router.post('/signup', authController.signupDoctor);
router.post('/login', authController.login);
router.post('/logout', authController.logout);
router.post('/forgotPassword', authController.forgotPassword);
router.patch('/resetPassword/:token', authController.resetPassword);

// Protected routes (authentication required)
router.use(authController.protect);

// Doctor-specific routes
router.get('/me', doctorController.getMe);
router.patch('/updateMe', doctorController.updateMe);
router.delete('/deleteMe', doctorController.deleteMe);
router.patch('/updateMyPassword', authController.updatePassword);
router.get('/myPatients', doctorController.getMyPatients);
router.post('/addPatient', doctorController.addPatientToDoctor);
router.post('/removePatient', doctorController.removePatientFromDoctor);

// Admin-only routes (MUST be at the end)
router.use(authController.restrictTo('admin'));
router.get('/', doctorController.getAllDoctors);

module.exports = router;
