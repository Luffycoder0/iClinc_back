const mongoose = require('mongoose');

const messageSchema = new mongoose.Schema(
  {
    sender: {
      type: mongoose.Schema.Types.ObjectId,
      refPath: 'senderModel',
      required: true
    },
    senderModel: {
      type: String,
      required: true,
      enum: ['Doctor', 'Patient']
    },
    receiver: {
      type: mongoose.Schema.Types.ObjectId,
      refPath: 'receiverModel',
      required: true
    },
    receiverModel: {
      type: String,
      required: true,
      enum: ['Doctor', 'Patient']
    },
    message: {
      type: String,
      required: [true, "Msg can't be empty"],
      trim: true,
      maxlength: 1000
    },
    read: {
      type: Boolean,
      default: false
    }
  },
  {
    timestamps: true
  }
);

messageSchema.index({ sender: 1, receiver: 1 });
messageSchema.index({ createdAt: -1 });

const Message = mongoose.model('Message', messageSchema);
module.exports = Message;
