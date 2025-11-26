const express = require('express');
const messageController = require('../controllers/msgController');
const authController = require('../controllers/authController');

const router = express.Router();

router.use(authController.protect);

router.post('/send', messageController.sendMessage);
router.get('/chats', messageController.getMyChats);
router.get('/conv/:otherId', messageController.getConversation);

module.exports = router;
