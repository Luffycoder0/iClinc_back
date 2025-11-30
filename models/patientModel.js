const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const patientSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, 'Please provide your name']
    },
    phone: {
      type: String,
      required: [true, 'Please provide your phone number']
    },
    email: {
      type: String,
      required: [true, 'Please provide your email'],
      unique: true,
      lowercase: true
    },
    coName: {
      type: String
    },
    nationalID: {
      type: String,
      required: [true, 'Please provide your national ID'],
      unique: true
    },
    gender: {
      type: String,
      enum: ['male', 'female'],
      required: [true, 'Please specify your gender']
    },
    address: {
      type: String,
      required: [true, 'Please provide your address']
    },
    dateOfBirth: {
      type: Date
    },
    aboutMe: {
      type: String
    },
    medicalHistory: {
      type: String
    },
    allergies: {
      type: String
    },
    bloodType: {
      type: String,
      enum: ['A+', 'A-', 'B+', 'B-', 'AB+', 'AB-', 'O+', 'O-', '']
    },
    emergencyContact: {
      type: String
    },
    insurance: {
      type: String
    },
    photo: {
      type: String
    },
    patientDisease: {
      type: String
    },
    password: {
      type: String,
      required: [true, 'Please provide a password'],
      minlength: 6,
      select: false
    },
    passwordConfirm: {
      type: String,
      required: [true, 'Please confirm your password'],
      validate: {
        validator: function (el) {
          return el === this.password;
        },
        message: 'Passwords do not match'
      }
    },
    passwordChangedAt: Date,
    passwordResetToken: String,
    passwordResetExpires: Date,
    active: {
      type: Boolean,
      default: true,
      select: false
    },
    doctors: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Doctor'
      }
    ]
  },
  {
    timestamps: true
  }
);

// Hash password before saving
patientSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);
  this.passwordConfirm = undefined;
  next();
});

// Update passwordChangedAt when password is modified
patientSchema.pre('save', function (next) {
  if (!this.isModified('password') || this.isNew) return next();
  this.passwordChangedAt = Date.now() - 1000;
  next();
});

// Filter out inactive users in queries
patientSchema.pre(/^find/, function (next) {
  this.find({ active: { $ne: false } });
  next();
});

// Compare passwords
patientSchema.methods.correctPassword = async function (
  candidatePassword,
  userPassword
) {
  return await bcrypt.compare(candidatePassword, userPassword);
};

// Check if password was changed after JWT was issued
patientSchema.methods.changedPasswordAfter = function (JWTTimestamp) {
  if (this.passwordChangedAt) {
    const changedTimestamp = parseInt(
      this.passwordChangedAt.getTime() / 1000,
      10
    );
    return JWTTimestamp < changedTimestamp;
  }
  return false;
};

const Patient = mongoose.model('Patient', patienتSchema);
module.exports = Patient;
