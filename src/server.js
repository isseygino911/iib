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
import { send } from './utils/mailer.js';

dotenv.config();

const app  = express();
const PORT = process.env.PORT || 5003;

app.set('trust proxy', 1);

// ── Security middleware ──────────────────────────────────────
const ALLOWED_ORIGINS = [
  'http://localhost:5173',
  'https://iidesign.cloud',
  'https://api.iidesign.cloud',
];

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
// Bodies are capped well below the Express default (100kb). The largest
// legitimate payload is a contact brief, which is limited to 2000 chars.
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
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
 * Accepts a commission enquiry form submission and emails it to CONTACT_NOTIFY_EMAIL.
 */
app.post('/api/contact', apiLimiter, async (req, res) => {
  const { name, email, projectType, brief } = req.body;

  if (!name || !email || !brief)
    return res.status(400).json({ message: 'Name, email, and project brief are required.' });

  // Type-check before any length check: on a non-string, `.length` is either
  // undefined (silently skipping the cap) or the wrong thing entirely.
  if (typeof name !== 'string' || typeof email !== 'string' || typeof brief !== 'string')
    return res.status(400).json({ message: 'Name, email, and project brief must be text.' });

  if (projectType !== undefined && typeof projectType !== 'string')
    return res.status(400).json({ message: 'Project type must be text.' });

  if (!isValidEmail(email))
    return res.status(400).json({ message: 'Invalid email address.' });

  if (name.length > 100)
    return res.status(400).json({ message: 'Name must be 100 characters or fewer.' });

  if (brief.length > 2000) {
    return res.status(400).json({ message: 'Brief must be 2000 characters or fewer.' });
  }

  // The email is the only record of the enquiry, so a failed send fails the request
  // and the visitor can retry rather than believing it was delivered.
  try {
    await send({
      to:      process.env.CONTACT_NOTIFY_EMAIL,
      replyTo: email,
      subject: `New enquiry — ${name.replace(/[\r\n]+/g, ' ')}`,
      text:    `Name: ${name}\nEmail: ${email}\nProject type: ${projectType || '—'}\n\n${brief}`,
    });
  } catch (err) {
    console.error('[contact] Email send failed:', err.message);
    return res.status(502).json({ message: 'Your enquiry could not be sent. Please try again shortly.' });
  }

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
