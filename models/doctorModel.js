const mongoose = require('mongoose');
const validator = require('validator');
const bcrypt = require('bcryptjs');

const doctorSchema = new mongoose.Schema({
  fullName: {
    type: String,
    required: [true, 'Tell us your name']
  },
  clinicName: {
    type: String,
    required: [true, 'Provide your clinic name!']
  },
  licenseID: {
    type: String,
    required: [true, 'Provide your license ID']
  },
  nationalID: {
    type: String,
    required: [true, 'Provide a valid national ID'],
    validate: {
      validator: (val) => /^\d{14}$/.test(val),
      message: 'National ID must be 14 digits'
    }
  },
  gender: {
    type: String,
    enum: ['Male', 'Female']
  },
  email: {
    type: String,
    required: [true, 'Provide a valid email address'],
    unique: true,
    lowercase: true,
    validate: [validator.isEmail, 'Please provide a valid email']
  },
  phone: String,
  password: {
    type: String,
    required: [true, 'Provide a password'],
    minlength: 8,
    select: false
  },
  passwordConfirm: {
    type: String,
    required: [true, 'Confirm your password'],
    validate: {
      validator: function (el) {
        return el === this.password;
      },
      message: 'Passwords are not the same!'
    }
  },
  passwordChangedAt: Date,
  passwordResetToken: String,
  passwordResetExpires: Date,
  active: {
    type: Boolean,
    default: true
  },
  role: {
    type: String,
    default: 'doctor'
  },
  address: {
    type: String
  },
  rate: {
    type: Number,
    default: 4.5
  },
  patients: [
    {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Patient'
    }
  ],
  aboutMe: {
    type: String,
    default: ''
  },
  specialities: {
    type: String,
    enum: ['Neurology', 'Cardiology', 'Dermatology', 'Pediatrics', ''],
    default: ''
  },
  designation: {
    type: String,
    default: ''
  },
  experience: {
    type: String,
    default: ''
  },
  education: {
    type: String,
    default: ''
  }
});

doctorSchema.index({ location: '2dsphere' });

doctorSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);
  this.passwordConfirm = undefined;
  next();
});

doctorSchema.methods.correctPassword = async function (candidate, userPwd) {
  return await bcrypt.compare(candidate, userPwd);
};

const Doctor = mongoose.model('Doctor', doctorSchema);
module.exports = Doctor;
