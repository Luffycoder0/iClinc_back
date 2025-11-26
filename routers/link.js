const express = require('express');
const linkController = require('../controllers/linkController');

const router = express.Router();

// Linker
router.post('/link', linkController.linkDoctorPatient);

// Get lists
router.get('/doctor/:doctorId/patients', linkController.getDoctorPatients);
router.get('/patient/:patientId/doctors', linkController.getPatientDoctors);

module.exports = router;
