const mongoose = require('mongoose');
const dotenv = require('dotenv');
const http = require('http');
const { Server } = require('socket.io');
const app = require('./app');

dotenv.config({ path: './config.env' });

process.on('uncaughtException', (err) => {
  console.error('💥 UNCAUGHT EXCEPTION 💥');
  console.error(err.name, err.message);
  process.exit(1);
});

const DB = process.env.DATABASE.replace(
  '<PASSWORD>',
  process.env.DATABASE_PASSWORD
);

mongoose
  .connect(DB, {
    useNewUrlParser: true,
    useUnifiedTopology: true
  })
  .then(() => console.log('DB connected successfully'))
  .catch((err) => {
    console.error('Database connection failed:', err);
    process.exit(1);
  });

const server = http.createServer(app);

const io = new Server(server, {
  cors: {
    origin: '*',
    methods: ['GET', 'POST', 'PATCH', 'DELETE']
  }
});

app.set('io', io);
global.io = io;

io.on('connection', (socket) => {
  console.log(`User connected: ${socket.id}`);

  socket.on('joinUser', ({ userId, role }) => {
    if (userId) {
      socket.join(userId.toString());
      console.log(`${role} ${userId} joined their room`);
    }
  });

  socket.on(
    'sendMessage',
    ({ senderId, senderModel, receiverId, receiverModel, message }) => {
      const messageData = {
        sender: senderId,
        senderModel,
        receiver: receiverId,
        receiverModel,
        message,
        createdAt: new Date()
      };

      io.to(receiverId.toString()).emit('newMessage', messageData);
      io.to(senderId.toString()).emit('newMessage', messageData);
    }
  );

  socket.on('typing', ({ senderId, receiverId, isTyping }) => {
    io.to(receiverId.toString()).emit('userTyping', { senderId, isTyping });
  });

  socket.on('disconnect', () => {
    console.log(`User disconnected: ${socket.id}`);
  });
});

const PORT = process.env.PORT || 5000;

server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

process.on('unhandledRejection', (err) => {
  console.error('💥 UNHANDLED REJECTION 💥');
  console.error(err.name, err.message);
  server.close(() => {
    process.exit(1);
  });
});
