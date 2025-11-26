const express = require('express');
const adminController = require('../controllers/adminController');
const authController = require('../controllers/authController');

const router = express.Router();

router.post('/signup', adminController.signup);
router.post('/login', adminController.login);
router.get('/doctors', authController.protect, adminController.getAllDoctors);
router.get('/patients', authController.protect, adminController.getAllPatients);

module.exports = router;
