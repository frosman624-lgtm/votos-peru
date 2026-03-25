const express = require("express");
const session = require("express-session");
const { createClient } = require("@supabase/supabase-js");
const nodemailer = require("nodemailer");
const bcrypt = require("bcryptjs");
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
  "TU_SUPABASE_KEY"
);

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: "shieldgramorganization@gmail.com",
    pass: "wyknehhgagbtejeq",
  },
});

app.get("/", (req, res) => {
  res.sendFile(__dirname + "/index.html");
});

app.post("/register", async (req, res) => {
  const { email, name, password } = req.body;

  const hash = await bcrypt.hash(password, 10);
  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  const otp_exp = new Date(Date.now() + 10 * 60 * 1000);

  await supabase.from("users").insert([
    {
      email,
      name,
      password_hash: hash,
      otp_code: otp,
      otp_expires_at: otp_exp,
    },
  ]);

  await transporter.sendMail({
    from: "shieldgramorganization@gmail.com",
    to: email,
    subject: "Codigo de verificacion",
    text: "Tu codigo es: " + otp,
  });

  res.send("Registro exitoso");
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

  await supabase.from("votes").insert([
    {
      user_id: req.session.user_id,
      candidate_id: candidate,
      ip_hash: ip_hash,
    },
  ]);

  res.send("Voto registrado");
});

app.get("/results", async (req, res) => {
  const { data } = await supabase.from("public_results").select("*");
  res.json(data);
});

app.listen(3000, () => {
  console.log("Servidor corriendo");
});