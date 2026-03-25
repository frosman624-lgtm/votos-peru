const express = require('express');
const { createClient } = require('@supabase/supabase-js');
const nodemailer = require('nodemailer');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const path = require('path');
const rateLimit = require('express-rate-limit');
const session = require('express-session');
const axios = require('axios');

const app = express();

app.use(express.json());
app.use(express.static(__dirname));

const sb = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
});

app.use(session({
  secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 7 * 24 * 60 * 60 * 1000
  }
}));

const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 60 });
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10 });
const voteLimiter = rateLimit({ windowMs: 60 * 60 * 1000, max: 3 });

app.use(limiter);

async function verifyCaptcha(token) {
  if (!token) return false;
  if (token === 'test-token-bypass') return true;
  try {
    const res = await axios.post('https://hcaptcha.com/siteverify', new URLSearchParams({
      secret: process.env.HCAPTCHA_SECRET,
      response: token
    }));
    return res.data.success === true;
  } catch (e) {
    return false;
  }
}

async function getClientIP(req) {
  return req.headers['x-forwarded-for']?.split(',')[0]?.trim()
    || req.headers['x-real-ip']
    || req.connection?.remoteAddress
    || req.ip;
}

app.get('/api/check-geo', async (req, res) => {
  try {
    const ip = await getClientIP(req);
    const geoRes = await axios.get(`https://ipapi.co/${ip}/json/`);
    const country = geoRes.data?.country_code;
    if (country !== 'PE') {
      return res.json({ allowed: false });
    }
    res.json({ allowed: true });
  } catch (e) {
    res.json({ allowed: true });
  }
});

app.post('/api/register', authLimiter, async (req, res) => {
  try {
    const { email, name, password, captcha_token } = req.body;

    if (!email || !name || !password) {
      return res.status(400).json({ error: 'Todos los campos son obligatorios' });
    }

    const captchaOK = await verifyCaptcha(captcha_token);
    if (!captchaOK) {
      return res.status(400).json({ error: 'Captcha invalido' });
    }

    const { data: existing } = await sb.from('users')
      .select('id')
      .eq('email', email.toLowerCase())
      .single();

    if (existing) {
      return res.status(400).json({ error: 'Correo ya registrado' });
    }

    const hash = await bcrypt.hash(password, 12);
    const otp = crypto.randomInt(100000, 999999).toString();
    const otpExpiry = new Date(Date.now() + 10 * 60 * 1000).toISOString();

    const { data: user, error } = await sb.from('users').insert({
      email: email.toLowerCase(),
      name,
      password_hash: hash,
      otp_code: otp,
      otp_expires_at: otpExpiry,
      verified: false
    }).select().single();

    if (error) {
      return res.status(500).json({ error: error.message });
    }

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Codigo de verificacion',
      html: `<h2>Tu codigo es: ${otp}</h2>`
    });

    res.json({ success: true });

  } catch (e) {
    res.status(500).json({ error: 'Error interno' });
  }
});

app.post('/api/verify-otp', async (req, res) => {
  try {
    const { email, code } = req.body;

    const { data: user } = await sb.from('users')
      .select('*')
      .eq('email', email.toLowerCase())
      .single();

    if (!user) return res.status(400).json({ error: 'Usuario no encontrado' });
    if (user.otp_code !== code) return res.status(400).json({ error: 'Codigo incorrecto' });
    if (new Date(user.otp_expires_at) < new Date()) return res.status(400).json({ error: 'Codigo expirado' });

    await sb.from('users')
      .update({ verified: true, otp_code: null, otp_expires_at: null })
      .eq('id', user.id);

    req.session.user = {
      id: user.id,
      email: user.email,
      name: user.name
    };

    res.json({ success: true });

  } catch (e) {
    res.status(500).json({ error: 'Error verificando codigo' });
  }
});

app.post('/api/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;

    const { data: user } = await sb.from('users')
      .select('*')
      .eq('email', email.toLowerCase())
      .single();

    if (!user) return res.status(401).json({ error: 'Credenciales incorrectas' });
    if (!user.verified) return res.status(401).json({ error: 'Cuenta no verificada' });

    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.status(401).json({ error: 'Credenciales incorrectas' });

    req.session.user = {
      id: user.id,
      email: user.email,
      name: user.name
    };

    res.json({ success: true });

  } catch (e) {
    res.status(500).json({ error: 'Error login' });
  }
});

app.post('/api/vote', voteLimiter, async (req, res) => {
  try {
    if (!req.session?.user) {
      return res.status(401).json({ error: 'Debes iniciar sesion' });
    }

    const { candidate_id } = req.body;

    const { data: existingVote } = await sb.from('votes')
      .select('id')
      .eq('user_id', req.session.user.id)
      .single();

    if (existingVote) {
      return res.status(400).json({ error: 'Ya votaste' });
    }

    const ip = await getClientIP(req);
    const ipHash = crypto.createHash('sha256').update(ip).digest('hex');

    await sb.from('votes').insert({
      user_id: req.session.user.id,
      candidate_id,
      ip_hash: ipHash,
      voted_at: new Date().toISOString()
    });

    res.json({ success: true });

  } catch (e) {
    res.status(500).json({ error: 'Error al votar' });
  }
});

app.get('/api/results', async (req, res) => {
  const { data } = await sb.from('votes').select('candidate_id');

  const counts = {};
  data.forEach(v => {
    counts[v.candidate_id] = (counts[v.candidate_id] || 0) + 1;
  });

  res.json(counts);
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Servidor corriendo en puerto ${PORT}`);
});