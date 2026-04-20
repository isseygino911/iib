import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';

import { testConnection } from './config/db.js';
import authRouter      from './routes/authRoutes.js';
import userRouter      from './routes/userRoutes.js';
import dashboardRouter from './routes/dashboardRoutes.js';
import { PROJECTS } from './data/projects.js';
import { apiLimiter, errorHandler, notFoundHandler } from './middleware/index.js';
import { isValidEmail } from './utils/auth.js';

dotenv.config();

if (process.env.NODE_ENV === 'production' && !process.env.CORS_ORIGIN) {
  console.error('[server] FATAL: CORS_ORIGIN env var must be set in production');
  process.exit(1);
}

const app  = express();
const PORT = process.env.PORT || 5003;

app.set('trust proxy', 1);

// ── Security middleware ──────────────────────────────────────
const ALLOWED_ORIGINS = (process.env.CORS_ORIGIN || 'http://localhost:5173')
  .split(',')
  .map((o) => o.trim());

app.use(helmet());
app.use(cors({
  origin: (origin, cb) => {
    // Allow requests with no origin (curl, server-to-server)
    if (!origin || ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
    cb(new Error(`CORS: origin ${origin} not allowed`));
  },
  credentials: true,
}));

// ── Body / cookie parsing ────────────────────────────────────
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// ── Routes ───────────────────────────────────────────────────
app.use('/api/auth',      authRouter);
app.use('/api/users',     apiLimiter, userRouter);
app.use('/api/dashboard', dashboardRouter);

/**
 * GET /api/projects
 * Returns the full list of portfolio projects.
 */
app.get('/api/projects', apiLimiter, (req, res) => {
  res.json(PROJECTS);
});

/**
 * GET /api/projects/:key
 * Returns a single project by its unique key.
 */
app.get('/api/projects/:key', apiLimiter, (req, res) => {
  const project = PROJECTS.find(p => p.key === req.params.key);
  if (!project) {
    return res.status(404).json({ message: 'Project not found' });
  }
  res.json(project);
});

/**
 * POST /api/contact
 * Accepts a commission enquiry form submission.
 * Returns 200 ok — email delivery would be wired here in production.
 */
app.post('/api/contact', apiLimiter, (req, res) => {
  const { name, email, projectType, brief } = req.body;

  if (!name || !email || !brief)
    return res.status(400).json({ message: 'Name, email, and project brief are required.' });

  if (!isValidEmail(email))
    return res.status(400).json({ message: 'Invalid email address.' });

  if (brief.length > 2000) {
    return res.status(400).json({ message: 'Brief must be 2000 characters or fewer.' });
  }

  console.log('[contact] New enquiry from:', email, '— name:', name, '— type:', projectType);
  res.json({ ok: true, message: 'Enquiry received. We will be in touch.' });
});

// ── 404 / Error handlers ─────────────────────────────────────
app.use(notFoundHandler);
app.use(errorHandler);

// ── Start ────────────────────────────────────────────────────
async function start() {
  await testConnection();
  app.listen(PORT, () => {
    console.log(`[server] II Design API running on http://localhost:${PORT}`);
  });
}

start();
