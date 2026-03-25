const express = require("express");
const session = require("express-session");
const { createClient } = require("@supabase/supabase-js");
const crypto = require("crypto");

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname));

app.use(
  session({
    secret: process.env.SESSION_SECRET || "voto2026secret",
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, maxAge: 24 * 60 * 60 * 1000 },
  })
);

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_KEY
);

app.get("/api/check-geo", (req, res) => {
  res.json({ allowed: true });
});

app.get("/api/session", (req, res) => {
  if (req.session.user) return res.json({ user: req.session.user });
  res.json({ user: null });
});

app.post("/api/register", async (req, res) => {
  const { name } = req.body;
  if (!name || name.trim().length < 2)
    return res.status(400).json({ error: "Ingresa tu nombre completo" });

  const id = crypto.randomUUID();
  const userData = { id, name: name.trim() };

  const { error } = await supabase.from("users").insert([userData]);
  if (error) return res.status(500).json({ error: "Error al registrar: " + error.message });

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
  if (!req.session.user) return res.status(401).json({ error: "Debes ingresar tu nombre primero" });

  const { candidate_id } = req.body;
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
  const { data, error } = await supabase.from("votes").select("candidate_id");

  if (error) return res.status(500).json({ error: "Error cargando resultados" });

  const counts = {};
  (data || []).forEach(v => {
    counts[v.candidate_id] = (counts[v.candidate_id] || 0) + 1;
  });

  const results = Object.entries(counts).map(([candidate_id, count]) => ({ candidate_id, count }));
  const total = results.reduce((s, r) => s + r.count, 0);

  res.json({ results, total });
});

app.listen(3000, () => console.log("Servidor corriendo en http://localhost:3000"));