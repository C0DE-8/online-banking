// server.js
require('dotenv').config();
const express = require('express');
const db = require('./db');
const authRoutes = require('./routes/authRoutes');
const adminRoutes = require('./routes/adminRoutes');
const userRoutes = require('./routes/userRoutes');
const cors = require('cors');
const { ensureTransferSchema } = require('./utils/ensureTransferSchema');
const {
  ERROR_LOG_FILE,
  appendErrorLog,
  requestFailureLogger,
  expressErrorLogger,
} = require('./utils/errorLogger');

const app = express();

// Enable CORS
app.use(cors({
  origin: '*', // or replace '*' with your frontend URL, e.g., 'http://localhost:3000'
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
  credentials: true
}));

// In server.js or app.js
app.use('/uploads', express.static('uploads'));

app.use(requestFailureLogger);

app.use(express.json());

app.use('/api/auth', authRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api/user', userRoutes);

app.get('/', (req, res) => {
  res.send('Backend Running ✅');
});

app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

app.use(expressErrorLogger);

const PORT = process.env.PORT || 5000;
ensureTransferSchema()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`🚀 Server running on port http://localhost:${PORT}`);
      console.log(`API error log: ${ERROR_LOG_FILE}`);
    });
  })
  .catch((err) => {
    appendErrorLog({
      timestamp: new Date().toISOString(),
      scope: 'startup',
      error: {
        name: err.name,
        message: err.message || String(err),
        stack: err.stack,
        code: err.code,
        errno: err.errno,
        sqlMessage: err.sqlMessage,
        sqlState: err.sqlState,
      },
    });
    console.error('❌ Failed to prepare transfer schema:', err);
    process.exit(1);
  });
