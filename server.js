const express = require("express");
const session = require("express-session");
const { createClient } = require("@supabase/supabase-js");
const nodemailer = require("nodemailer");
const bcrypt = require("bcryptjs");
const path = require("path");
const crypto = require("crypto");

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(
  session({
    secret: "clave_super_secreta_2026",
    resave: false,
    saveUninitialized: false,
  })
);

const supabase = createClient(
  "https://lmrkjbyjzoztmyyeccdt.supabase.co",
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImxtcmtqYnlqem96dG15eWVjY2R0Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzQzOTkyMzYsImV4cCI6MjA4OTk3NTIzNn0.k9pJ5yp4zvDdLH8VyqkAb86sp4Jb6aKYtYZLKwsAnKo"
);

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: "shieldgramorganization@gmail.com",
    pass: "wyknehhgagbtejeq",
  },
});

app.use(express.static("public"));

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.post("/register", async (req, res) => {
  const { email, name, password } = req.body;

  const hash = await bcrypt.hash(password, 10);
  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  const otp_exp = new Date(Date.now() + 10 * 60 * 1000);

  const { data, error } = await supabase
    .from("users")
    .insert([
      {
        email,
        name,
        password_hash: hash,
        otp_code: otp,
        otp_expires_at: otp_exp,
      },
    ])
    .select()
    .single();

  if (error) return res.send("Error registro");

  await transporter.sendMail({
    from: "shieldgramorganization@gmail.com",
    to: email,
    subject: "Codigo de verificacion",
    text: "Tu codigo es: " + otp,
  });

  res.send("Registro exitoso, revisa tu correo");
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const { data } = await supabase
    .from("users")
    .select("*")
    .eq("email", email)
    .single();

  if (!data) return res.send("Usuario no existe");

  const valid = await bcrypt.compare(password, data.password_hash);

  if (!valid) return res.send("Password incorrecto");

  req.session.user_id = data.id;

  res.send("Login correcto");
});

app.post("/vote", async (req, res) => {
  if (!req.session.user_id) return res.send("Login primero");

  const { candidate } = req.body;

  const ip =
    req.headers["x-forwarded-for"] || req.socket.remoteAddress || "";
  const ip_hash = crypto.createHash("sha256").update(ip).digest("hex");

  const { error } = await supabase.from("votes").insert([
    {
      user_id: req.session.user_id,
      candidate_id: candidate,
      ip_hash: ip_hash,
    },
  ]);

  if (error) return res.send("Ya votaste o error");

  res.send("Voto registrado");
});

app.get("/results", async (req, res) => {
  const { data } = await supabase.from("public_results").select("*");
  res.json(data);
});

const PORT = 3000;

app.listen(PORT, () => {
  console.log("Servidor corriendo en puerto 3000");
});