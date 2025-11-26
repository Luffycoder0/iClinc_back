const mongoose = require('mongoose');
const validator = require('validator');
const bcrypt = require('bcryptjs');

const patientSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, 'Please tell us your full name']
  },
  email: {
    type: String,
    required: [true, 'Please provide your email address'],
    unique: true,
    lowercase: true,
    validate: [validator.isEmail, 'Please provide a valid email']
  },
  address: {
    type: String
  },
  phone: {
    type: String,
    required: [true, 'Please provide your phone number']
  },
  nationalID: {
    type: String,
    validate: {
      validator: (val) => /^\d{14}$/.test(val),
      message: 'National ID must be 14 digits'
    }
  },
  gender: {
    type: String
  },
  patientDisease: String,
  password: {
    type: String,
    required: [true, 'Please provide a password'],
    minlength: 8,
    select: false
  },
  passwordConfirm: {
    type: String,
    validate: {
      validator: function (el) {
        return el === this.password;
      },
      message: 'Passwords do not match!'
    }
  },
  passwordChangedAt: Date,
  passwordResetToken: String,
  passwordResetExpires: Date,
  active: {
    type: Boolean,
    default: true
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  role: {
    type: String,
    default: 'patient'
  },
  doctors: [
    {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Doctor'
    }
  ]
});

// Hash password before saving
patientSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);
  this.passwordConfirm = undefined;
  next();
});

patientSchema.methods.correctPassword = async function (candidate, userPwd) {
  return await bcrypt.compare(candidate, userPwd);
};

const Patient = mongoose.model('Patient', patientSchema);
module.exports = Patient;
