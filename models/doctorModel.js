const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const doctorSchema = new mongoose.Schema(
  {
    fullName: {
      type: String,
      required: [true, 'Please provide your full name']
    },
    clinicName: {
      type: String,
      required: [true, 'Please provide your clinic name']
    },
    licenseID: {
      type: String,
      required: [true, 'Please provide your license ID'],
      unique: true
    },
    email: {
      type: String,
      required: [true, 'Please provide your email'],
      unique: true,
      lowercase: true
    },
    phone: {
      type: String,
      required: [true, 'Please provide your phone number']
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
    patients: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Patient'
      }
    ]
  },
  {
    timestamps: true
  }
);

// Hash password before saving
doctorSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();

  this.password = await bcrypt.hash(this.password, 12);
  this.passwordConfirm = undefined;
  next();
});

// Update passwordChangedAt when password is modified
doctorSchema.pre('save', function (next) {
  if (!this.isModified('password') || this.isNew) return next();

  this.passwordChangedAt = Date.now() - 1000;
  next();
});

// Filter out inactive users in queries
doctorSchema.pre(/^find/, function (next) {
  this.find({ active: { $ne: false } });
  next();
});

// Compare passwords
doctorSchema.methods.correctPassword = async function (
  candidatePassword,
  userPassword
) {
  return await bcrypt.compare(candidatePassword, userPassword);
};

// Check if password was changed after JWT was issued
doctorSchema.methods.changedPasswordAfter = function (JWTTimestamp) {
  if (this.passwordChangedAt) {
    const changedTimestamp = parseInt(
      this.passwordChangedAt.getTime() / 1000,
      10
    );
    return JWTTimestamp < changedTimestamp;
  }
  return false;
};

const Doctor = mongoose.model('Doctor', doctorSchema);

module.exports = Doctor;
