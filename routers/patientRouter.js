const express = require('express');
const patientController = require('../controllers/patientController');
const authController = require('../controllers/authController');

///////////////////////////////////
// Patient Routes
///////////////////////////////////
const router = express.Router();

router.post('/signup', authController.signupPatient);
router.post('/login', authController.login);
router.post('/logout', authController.logout);

router.post('/forgotPassword', authController.forgotPassword);
router.patch('/resetPassword/:token', authController.resetPassword);

router.use(authController.protect);

router.get('/me', patientController.getMe);
router.patch('/updateMe', patientController.updateMe);
router.delete('/deleteMe', patientController.deleteMe);
router.patch('/updateMyPassword', authController.updatePassword);

router.get('/doctors', authController.protect, patientController.getAllDoctors);
router.get('/myDoctors', patientController.getMyDoctors);
router.post('/addDoctor', patientController.addDoctorToPatient);
router.post('/removeDoctor', patientController.removeDoctorFromPatient);

router.use(authController.restrictTo('admin'));
router.get('/', patientController.getAllPatients);

module.exports = router;
