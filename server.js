const express = require("express");
const session = require("express-session");
const { createClient } = require("@supabase/supabase-js");
const nodemailer = require("nodemailer");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname));

app.use(
  session({
    secret: "clave_super_secreta_2026",
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, maxAge: 24 * 60 * 60 * 1000 },
  })
);

const supabase = createClient(
  "https://lmrkjbyjzoztmyyeccdt.supabase.co",
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImxtcmtqYnlqem96dG15eWVjY2R0Iiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc3NDM5OTIzNiwiZXhwIjoyMDg5OTc1MjM2fQ.ZEvc7Mjs6tYvmSRRlqcJB2sw-YMNy47h-tczp_Fx7zA"
);

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: "shieldgramorganization@gmail.com",
    pass: "wyknehhgagbtejeq",
  },
});

app.get("/api/check-geo", async (req, res) => {
  res.json({ allowed: true });
});

app.get("/api/session", (req, res) => {
  if (req.session.user) {
    return res.json({ user: req.session.user });
  }
  res.json({ user: null });
});

app.post("/api/register", async (req, res) => {
  const { email, name, password, captcha_token } = req.body;

  if (!email || !name || !password)
    return res.status(400).json({ error: "Todos los campos son obligatorios" });

  if (password.length < 8)
    return res.status(400).json({ error: "La contraseña debe tener al menos 8 caracteres" });

  const { data: existing } = await supabase
    .from("users")
    .select("id, verified")
    .eq("email", email)
    .single();

  if (existing && existing.verified)
    return res.status(400).json({ error: "Este correo ya está registrado. Inicia sesión." });

  const hash = await bcrypt.hash(password, 10);
  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  const otp_exp = new Date(Date.now() + 10 * 60 * 1000);

  if (existing) {
    await supabase
      .from("users")
      .update({ name, password_hash: hash, otp_code: otp, otp_expires_at: otp_exp })
      .eq("email", email);
  } else {
    const { error } = await supabase.from("users").insert([
      { email, name, password_hash: hash, otp_code: otp, otp_expires_at: otp_exp, verified: false },
    ]);
    if (error) return res.status(500).json({ error: "Error al crear usuario: " + error.message });
  }

  try {
    await transporter.sendMail({
      from: '"Voto Online Peru 2026" <shieldgramorganization@gmail.com>',
      to: email,
      subject: "Tu código de verificación - Voto Online Peru 2026",
      html: `
        <div style="font-family:sans-serif;max-width:400px;margin:0 auto;padding:20px">
          <h2 style="color:#cc0000">Código de Verificación</h2>
          <p>Hola <strong>${name}</strong>, tu código es:</p>
          <div style="font-size:2rem;font-weight:bold;letter-spacing:8px;color:#cc0000;
                      background:#fff5f5;padding:16px;border-radius:8px;text-align:center;margin:16px 0">
            ${otp}
          </div>
          <p style="color:#6b7280;font-size:.85rem">Válido por 10 minutos.</p>
        </div>
      `,
    });
  } catch (e) {
    console.error("Error enviando correo:", e.message);
    return res.status(500).json({ error: "No se pudo enviar el correo. Verifica tu dirección." });
  }

  res.json({ ok: true, message: "Código enviado" });
});

app.post("/api/verify-otp", async (req, res) => {
  const { email, code } = req.body;

  if (!email || !code)
    return res.status(400).json({ error: "Datos incompletos" });

  const { data: user } = await supabase
    .from("users")
    .select("*")
    .eq("email", email)
    .single();

  if (!user) return res.status(400).json({ error: "Usuario no encontrado" });
  if (user.otp_code !== code) return res.status(400).json({ error: "Código incorrecto" });
  if (new Date(user.otp_expires_at) < new Date())
    return res.status(400).json({ error: "El código ha expirado. Regístrate de nuevo." });

  await supabase.from("users").update({ verified: true, otp_code: null }).eq("email", email);

  const userData = { id: user.id, email: user.email, name: user.name };
  req.session.user = userData;
  res.json({ ok: true, user: userData });
});

app.post("/api/login", async (req, res) => {
  const { email, password, captcha_token } = req.body;

  if (!email || !password)
    return res.status(400).json({ error: "Ingresa tu correo y contraseña" });

  const { data: user } = await supabase
    .from("users")
    .select("*")
    .eq("email", email)
    .single();

  if (!user) return res.status(401).json({ error: "Correo no registrado" });
  if (!user.verified) return res.status(401).json({ error: "Cuenta no verificada. Regístrate primero." });

  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) return res.status(401).json({ error: "Contraseña incorrecta" });

  const userData = { id: user.id, email: user.email, name: user.name };
  req.session.user = userData;
  res.json({ ok: true, user: userData });
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get("/api/check-voted", async (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: "No autenticado" });

  const { data } = await supabase
    .from("votes")
    .select("id")
    .eq("user_id", req.session.user.id)
    .single();

  res.json({ voted: !!data });
});

app.post("/api/vote", async (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: "Debes iniciar sesión primero" });

  const { candidate_id, captcha_token } = req.body;
  if (!candidate_id) return res.status(400).json({ error: "Candidato no seleccionado" });

  const { data: existing } = await supabase
    .from("votes")
    .select("id")
    .eq("user_id", req.session.user.id)
    .single();

  if (existing) return res.status(400).json({ error: "Ya has emitido tu voto" });

  const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress || "";
  const ip_hash = crypto.createHash("sha256").update(ip).digest("hex");

  const { error } = await supabase.from("votes").insert([
    { user_id: req.session.user.id, candidate_id, ip_hash },
  ]);

  if (error) return res.status(500).json({ error: "Error al registrar voto: " + error.message });

  res.json({ ok: true });
});

app.get("/api/results", async (req, res) => {
  const { data, error } = await supabase
    .from("votes")
    .select("candidate_id");

  if (error) return res.status(500).json({ error: "Error cargando resultados" });

  const counts = {};
  (data || []).forEach(v => {
    counts[v.candidate_id] = (counts[v.candidate_id] || 0) + 1;
  });

  const results = Object.entries(counts).map(([candidate_id, count]) => ({ candidate_id, count }));
  const total = results.reduce((s, r) => s + r.count, 0);

  res.json({ results, total });
});

app.listen(3000, () => console.log("✅ Servidor corriendo en http://localhost:3000"));