const mongoose = require('mongoose');

const subscriptionSchema = new mongoose.Schema({
  patient: {
    type: mongoose.Schema.ObjectId,
    ref: 'Patient',
    required: [true, 'Subscription must belong to a patient']
  },
  doctor: {
    type: mongoose.Schema.ObjectId,
    ref: 'Doctor',
    required: [true, 'Subscription must belong to a doctor']
  },
  plan: {
    type: String,
    enum: ['basic', 'standard', 'premium'],
    required: [true, 'Please select a plan']
  },
  price: {
    type: Number,
    required: [true, 'Subscription must have a price']
  },
  serviceFee: {
    type: Number,
    default: 2
  },
  totalAmount: {
    type: Number,
    required: true
  },
  status: {
    type: String,
    enum: ['active', 'cancelled', 'expired'],
    default: 'active'
  },
  paymentStatus: {
    type: String,
    enum: ['paid', 'unpaid'],
    default: 'paid'
  },
  paymentMethod: {
    type: String,
    default: 'mock'
  },
  currentPeriodStart: {
    type: Date
  },
  currentPeriodEnd: {
    type: Date
  },
  cancelAtPeriodEnd: {
    type: Boolean,
    default: false
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Index to quickly check if patient has active subscription with doctor
subscriptionSchema.index({ patient: 1, doctor: 1, status: 1 });

// Method to check if subscription is currently active
subscriptionSchema.methods.isActive = function () {
  return (
    this.status === 'active' &&
    this.paymentStatus === 'paid' &&
    this.currentPeriodEnd > Date.now()
  );
};

// Static method to check if patient can access doctor
subscriptionSchema.statics.canAccess = async function (patientId, doctorId) {
  const subscription = await this.findOne({
    patient: patientId,
    doctor: doctorId,
    status: 'active',
    paymentStatus: 'paid',
    currentPeriodEnd: { $gt: Date.now() }
  });

  return !!subscription;
};

const Subscription = mongoose.model('Subscription', subscriptionSchema);
module.exports = Subscription;
