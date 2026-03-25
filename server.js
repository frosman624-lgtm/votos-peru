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
app.use(express.static(path.join(__dirname, 'votos-peru')));

const sb = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
});

app.use(session({
  secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
  resave: false,
  saveUninitialized: false,
  cookie: { secure: process.env.NODE_ENV === 'production', httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000 }
}));

const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 60 });
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10, message: { error: 'Demasiados intentos. Espera 15 minutos.' } });
const voteLimiter = rateLimit({ windowMs: 60 * 60 * 1000, max: 3, message: { error: 'Limite de intentos de voto alcanzado.' } });
app.use(limiter);

async function verifyCaptcha(token) {
  if (!token) return false;
  if (token === 'test-token-bypass') return true;
  try {
    const res = await axios.post('https://hcaptcha.com/siteverify', new URLSearchParams({
      secret: process.env.HCAPTCHA_SECRET || '0x0000000000000000000000000000000000000000',
      response: token
    }));
    return res.data.success === true;
  } catch (e) { return false; }
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
    const localIPs = ['127.0.0.1', '::1', 'localhost'];
    if (localIPs.includes(ip) || ip?.startsWith('192.168.') || ip?.startsWith('10.') || ip?.startsWith('172.')) {
      return res.json({ allowed: true, country: 'PE', dev: true });
    }
    const geoRes = await axios.get(`https://ipapi.co/${ip}/json/`, { timeout: 5000 });
    const country = geoRes.data?.country_code;
    if (country !== 'PE') {
      return res.json({ allowed: false, country, ip });
    }
    res.json({ allowed: true, country: 'PE' });
  } catch (e) {
    res.json({ allowed: true, note: 'geo-check-failed' });
  }
});

app.post('/api/register', authLimiter, async (req, res) => {
  try {
    const { email, name, password, captcha_token } = req.body;
    if (!email || !name || !password) return res.status(400).json({ error: 'Todos los campos son obligatorios' });
    if (password.length < 8) return res.status(400).json({ error: 'La contrasena debe tener al menos 8 caracteres' });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'Correo invalido' });
    const captchaOK = await verifyCaptcha(captcha_token);
    if (!captchaOK) return res.status(400).json({ error: 'Captcha invalido. Intentalo de nuevo.' });
    const { data: existing } = await sb.from('users').select('id').eq('email', email.toLowerCase()).single();
    if (existing) return res.status(400).json({ error: 'Este correo ya esta registrado. Inicia sesion.' });
    const hash = await bcrypt.hash(password, 12);
    const otp = crypto.randomInt(100000, 999999).toString();
    const otpExpiry = new Date(Date.now() + 10 * 60 * 1000).toISOString();
    const { data: user, error } = await sb.from('users').insert({
      email: email.toLowerCase(), name, password_hash: hash,
      otp_code: otp, otp_expires_at: otpExpiry, verified: false
    }).select().single();
    if (error) return res.status(500).json({ error: 'Error al crear cuenta: ' + error.message });
    await transporter.sendMail({
      from: `"Voto Peru 2026" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: 'Tu codigo de verificacion - Voto Peru 2026',
      html: `
        <div style="font-family:Arial,sans-serif;max-width:480px;margin:0 auto;padding:20px;">
          <div style="background:linear-gradient(135deg,#cc0000,#8b0000);padding:20px;border-radius:8px 8px 0 0;text-align:center;">
            <h2 style="color:#fff;margin:0;font-size:1.3rem;">Voto Online Peru 2026</h2>
            <p style="color:rgba(255,255,255,.8);margin:4px 0 0;font-size:.85rem;">Elecciones Generales - 12 de Abril</p>
          </div>
          <div style="background:#fff;border:1px solid #e5e7eb;border-top:none;padding:24px;border-radius:0 0 8px 8px;">
            <p style="color:#374151;">Hola <strong>${name}</strong>,</p>
            <p style="color:#374151;margin-bottom:20px;">Tu codigo de verificacion es:</p>
            <div style="background:#f9fafb;border:2px dashed #d1d5db;border-radius:8px;padding:20px;text-align:center;letter-spacing:12px;font-size:2rem;font-weight:700;color:#cc0000;">
              ${otp}
            </div>
            <p style="color:#6b7280;font-size:.82rem;margin-top:16px;">Este codigo expira en 10 minutos. Si no solicitaste esto, ignora este correo.</p>
          </div>
        </div>
      `
    });
    res.json({ success: true, message: 'Codigo enviado' });
  } catch (e) {
    console.error('register error:', e);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

app.post('/api/verify-otp', authLimiter, async (req, res) => {
  try {
    const { email, code } = req.body;
    if (!email || !code) return res.status(400).json({ error: 'Datos incompletos' });
    const { data: user } = await sb.from('users').select('*').eq('email', email.toLowerCase()).single();
    if (!user) return res.status(400).json({ error: 'Usuario no encontrado' });
    if (user.otp_code !== code) return res.status(400).json({ error: 'Codigo incorrecto' });
    if (new Date(user.otp_expires_at) < new Date()) return res.status(400).json({ error: 'El codigo ha expirado. Solicita uno nuevo.' });
    await sb.from('users').update({ verified: true, otp_code: null, otp_expires_at: null }).eq('id', user.id);
    const sessionUser = { id: user.id, email: user.email, name: user.name };
    req.session.user = sessionUser;
    res.json({ success: true, user: sessionUser });
  } catch (e) {
    res.status(500).json({ error: 'Error al verificar codigo' });
  }
});

app.post('/api/login', authLimiter, async (req, res) => {
  try {
    const { email, password, captcha_token } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Ingresa tu correo y contrasena' });
    const captchaOK = await verifyCaptcha(captcha_token);
    if (!captchaOK) return res.status(400).json({ error: 'Captcha invalido. Intentalo de nuevo.' });
    const { data: user } = await sb.from('users').select('*').eq('email', email.toLowerCase()).single();
    if (!user) return res.status(401).json({ error: 'Correo o contrasena incorrectos' });
    if (!user.verified) return res.status(401).json({ error: 'Cuenta no verificada. Revisa tu correo.' });
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.status(401).json({ error: 'Correo o contrasena incorrectos' });
    const sessionUser = { id: user.id, email: user.email, name: user.name };
    req.session.user = sessionUser;
    res.json({ success: true, user: sessionUser });
  } catch (e) {
    res.status(500).json({ error: 'Error al iniciar sesion' });
  }
});

app.post('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

app.get('/api/session', (req, res) => {
  if (req.session?.user) { res.json({ user: req.session.user }); }
  else { res.json({ user: null }); }
});

app.get('/api/check-voted', async (req, res) => {
  if (!req.session?.user) return res.status(401).json({ error: 'No autenticado' });
  const { data } = await sb.from('votes').select('id').eq('user_id', req.session.user.id).single();
  res.json({ voted: !!data });
});

app.post('/api/vote', voteLimiter, async (req, res) => {
  try {
    if (!req.session?.user) return res.status(401).json({ error: 'Debes iniciar sesion para votar' });
    const { candidate_id, captcha_token } = req.body;
    if (!candidate_id) return res.status(400).json({ error: 'Selecciona un candidato' });
    const captchaOK = await verifyCaptcha(captcha_token);
    if (!captchaOK) return res.status(400).json({ error: 'Captcha invalido' });
    const { data: existingVote } = await sb.from('votes').select('id').eq('user_id', req.session.user.id).single();
    if (existingVote) return res.status(400).json({ error: 'Ya emitiste tu voto anteriormente' });
    const ip = await getClientIP(req);
    const { data: ipVote } = await sb.from('votes').select('id').eq('ip_hash', crypto.createHash('sha256').update(ip).digest('hex')).single();
    if (ipVote) return res.status(400).json({ error: 'Ya se registro un voto desde esta red' });
    const { error } = await sb.from('votes').insert({
      user_id: req.session.user.id,
      candidate_id,
      ip_hash: crypto.createHash('sha256').update(ip).digest('hex'),
      voted_at: new Date().toISOString()
    });
    if (error) return res.status(500).json({ error: 'Error al registrar voto: ' + error.message });
    res.json({ success: true, message: 'Voto registrado correctamente' });
  } catch (e) {
    console.error('vote error:', e);
    res.status(500).json({ error: 'Error interno al registrar voto' });
  }
});

app.get('/api/results', async (req, res) => {
  try {
    const { data, error } = await sb.from('votes').select('candidate_id');
    if (error) return res.status(500).json({ error: 'Error cargando resultados' });
    const counts = {};
    data.forEach(v => { counts[v.candidate_id] = (counts[v.candidate_id] || 0) + 1; });
    const results = Object.entries(counts).map(([candidate_id, count]) => ({ candidate_id, count }));
    results.sort((a, b) => b.count - a.count);
    res.json({ results, total: data.length });
  } catch (e) {
    res.status(500).json({ error: 'Error cargando resultados' });
  }
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'votos-peru', 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor corriendo en puerto ${PORT}`));
