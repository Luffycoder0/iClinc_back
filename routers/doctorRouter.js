const express = require('express');
const doctorController = require('../controllers/doctorController');
const authController = require('../controllers/authController');

const router = express.Router();

// Public routes
router.post('/signup', authController.signupDoctor);
router.post('/login', authController.login);
router.post('/logout', authController.logout);
router.post('/forgotPassword', authController.forgotPassword);
router.post('/verifyResetCode', authController.verifyResetCode);
router.patch('/resetPassword/:token', authController.resetPassword);

// Protected routes
router.use(authController.protect);
router.get('/me', doctorController.getMe);
router.patch('/updateMe', doctorController.updateMe);
router.delete('/deleteMe', doctorController.deleteMe);
router.patch('/updateMyPassword', authController.updatePassword);
router.get('/myPatients', doctorController.getMyPatients);
router.post('/addPatient', doctorController.addPatientToDoctor);
router.post('/removePatient', doctorController.removePatientFromDoctor);

// Admin only
router.use(authController.restrictTo('admin'));
router.get('/', doctorController.getAllDoctors);

module.exports = router;
