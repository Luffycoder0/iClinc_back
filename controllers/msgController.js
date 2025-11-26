const Message = require('../models/msgModel');
const Doctor = require('../models/doctorModel');
const Patient = require('../models/patientModel');
const Subscription = require('../models/subscriptionModel');
const catchAsync = require('../utils/catchAsync');
const AppError = require('../utils/appError');
const mongoose = require('mongoose');

const capitalize = (s) => (s ? s.charAt(0).toUpperCase() + s.slice(1) : s);

exports.sendMessage = catchAsync(async (req, res, next) => {
  const { message, receiverId } = req.body;
  const senderRole = req.user.role;

  if (!message || !receiverId) {
    return next(new AppError('Receiver and message are required', 400));
  }

  const receiverModel = senderRole === 'doctor' ? 'Patient' : 'Doctor';

  // Subscription Check
  if (senderRole === 'patient') {
    const hasAccess = await Subscription.canAccess(req.user._id, receiverId);

    if (!hasAccess) {
      return next(
        new AppError(
          'You need an active subscription to message this doctor. Please subscribe first.',
          403
        )
      );
    }
  }

  const Receiver = receiverModel === 'Patient' ? Patient : Doctor;
  const receiver = await Receiver.findById(receiverId);
  if (!receiver) return next(new AppError('Receiver not found', 404));

  const newMessage = await Message.create({
    sender: req.user._id,
    senderModel: senderRole.charAt(0).toUpperCase() + senderRole.slice(1),
    receiver: receiverId,
    receiverModel,
    message
  });

  res.status(201).json({
    status: 'success',
    data: { message: newMessage }
  });
});

exports.getConversation = catchAsync(async (req, res, next) => {
  const { otherId } = req.params;
  const myId = req.user._id.toString();
  const myRole = req.user.role;

  if (!mongoose.Types.ObjectId.isValid(otherId)) {
    return next(new AppError('Invalid user id', 400));
  }

  // Subscription Check
  if (myRole === 'patient') {
    const hasAccess = await Subscription.canAccess(myId, otherId);

    if (!hasAccess) {
      return next(
        new AppError(
          'You need an active subscription to access this conversation. Please subscribe first.',
          403
        )
      );
    }
  }

  const messages = await Message.find({
    $or: [
      { sender: myId, receiver: otherId },
      { sender: otherId, receiver: myId }
    ]
  })
    .sort({ createdAt: 1 })
    .lean();

  await Message.updateMany(
    { sender: otherId, receiver: myId, read: false },
    { read: true }
  );

  res.status(200).json({
    status: 'success',
    results: messages.length,
    data: { messages }
  });
});

exports.getMyChats = catchAsync(async (req, res, next) => {
  const myId = mongoose.Types.ObjectId(req.user._id);
  const myRole = req.user.role;

  const chats = await Message.aggregate([
    {
      $match: {
        $or: [{ sender: myId }, { receiver: myId }]
      }
    },
    { $sort: { createdAt: -1 } },
    {
      $project: {
        sender: 1,
        senderModel: 1,
        receiver: 1,
        receiverModel: 1,
        message: 1,
        read: 1,
        createdAt: 1,
        counterpartId: {
          $cond: [{ $eq: ['$sender', myId] }, '$receiver', '$sender']
        },
        counterpartModel: {
          $cond: [{ $eq: ['$sender', myId] }, '$receiverModel', '$senderModel']
        }
      }
    },
    {
      $group: {
        _id: { id: '$counterpartId', model: '$counterpartModel' },
        lastMessage: { $first: '$message' },
        lastMessageTime: { $first: '$createdAt' },
        unreadCount: {
          $sum: {
            $cond: [
              {
                $and: [{ $eq: ['$receiver', myId] }, { $eq: ['$read', false] }]
              },
              1,
              0
            ]
          }
        }
      }
    },
    {
      $lookup: {
        from: 'patients',
        let: { cid: '$_id.id', m: '$_id.model' },
        pipeline: [
          {
            $match: {
              $expr: {
                $and: [{ $eq: ['$_id', '$$cid'] }, { $eq: ['Patient', '$$m'] }]
              }
            }
          },
          { $project: { fullName: '$name', photo: 1, email: 1 } }
        ],
        as: 'patientInfo'
      }
    },
    {
      $lookup: {
        from: 'doctors',
        let: { cid: '$_id.id', m: '$_id.model' },
        pipeline: [
          {
            $match: {
              $expr: {
                $and: [{ $eq: ['$_id', '$$cid'] }, { $eq: ['Doctor', '$$m'] }]
              }
            }
          },
          {
            $project: {
              fullName: '$fullName',
              photo: 1,
              email: 1,
              clinicName: 1
            }
          }
        ],
        as: 'doctorInfo'
      }
    },
    {
      $addFields: {
        counterpart: {
          $cond: [
            { $gt: [{ $size: '$patientInfo' }, 0] },
            { $arrayElemAt: ['$patientInfo', 0] },
            { $arrayElemAt: ['$doctorInfo', 0] }
          ]
        }
      }
    },
    {
      $project: {
        patientInfo: 0,
        doctorInfo: 0
      }
    },
    { $sort: { lastMessageTime: -1 } }
  ]);

  // If user is patient, add subscription status to each chat
  if (myRole === 'patient') {
    for (let chat of chats) {
      if (chat._id.model === 'Doctor') {
        const hasSubscription = await Subscription.canAccess(
          myId.toString(),
          chat._id.id.toString()
        );
        chat.hasActiveSubscription = hasSubscription;
      }
    }
  }

  res.status(200).json({
    status: 'success',
    results: chats.length,
    data: { chats }
  });
});
