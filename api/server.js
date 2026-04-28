import express from "express";
import cors from "cors";
import { createClient } from "@supabase/supabase-js";
import { MercadoPagoConfig, Preference } from "mercadopago";
import Stripe from "stripe";
import fetch from "node-fetch";
import crypto from "crypto";
import bcrypt from "bcrypt";
import rateLimit from "express-rate-limit";

// ─── CONFIGURACIÓN GLOBAL ────────────────────────────────────────────────────
const app = express();
const APPS_SCRIPT_URL =
  "https://script.google.com/macros/s/AKfycbzvcaYhHuyD-Xu63Aw9WpWrpcr5xmrgHW_IffXkmC90bs0pTzhWP1d8rWBaBuhG5Icx/exec";
const BCRYPT_ROUNDS  = 10;
const CACHE_DURATION = 20000;

// ─── VALIDADORES ─────────────────────────────────────────────────────────────
const getCleanSlug = (raw) => {
  if (!raw) return "";
  return raw.toLowerCase().trim()
    .normalize("NFD").replace(/[\u0300-\u036f]/g, "")
    .replace(/\s+/g, "-").replace(/[^a-z0-9-]/g, "");
};

const getCleanDomain = (raw) => {
  if (!raw) return "";
  return raw.replace(/^https?:\/\//, "").replace(/\/$/, "").toLowerCase().trim();
};

const validateEmail    = (e) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);
const validatePassword = (p) => p && p.length >= 6;
const validateDomain   = (d) => /^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]*[a-z0-9])?\.[a-z]{2,}$/.test(d);
const validatePhone    = (p) => /^[0-9\-\s\+]{5,20}$/.test(p);

// ─── CACHÉ ───────────────────────────────────────────────────────────────────
const globalCache = {};

// ─── RATE LIMITING ───────────────────────────────────────────────────────────
const limiterAuth    = rateLimit({ windowMs: 15 * 60 * 1000, max: 10, message: "Demasiados intentos.", standardHeaders: true, legacyHeaders: false });
const limiterBooking = rateLimit({ windowMs: 60 * 1000, max: 20, message: "Demasiadas reservas." });
const limiterAPI     = rateLimit({ windowMs: 60 * 1000, max: 200 });

// ─── CORS ────────────────────────────────────────────────────────────────────
app.use(cors({ origin: "*", methods: ["GET", "POST", "OPTIONS"], allowedHeaders: ["Content-Type", "Authorization", "x-api-key"] }));
app.use(express.json({ limit: "10mb" }));
app.use(limiterAPI);

// ─── SUPABASE ────────────────────────────────────────────────────────────────
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);

// ─── MIDDLEWARE: BEARER TOKEN ─────────────────────────────────────────────────
async function requireAuth(req, res, next) {
  try {
    const authHeader = req.headers["authorization"];
    if (!authHeader?.startsWith("Bearer ")) {
      return res.status(401).json({ success: false, error: "No autorizado: falta el token." });
    }
    const token  = authHeader.split(" ")[1];
    const domain = getCleanDomain(req.body?.domain || req.params?.domain || "");
    if (!token || !domain) {
      return res.status(401).json({ success: false, error: "No autorizado: datos incompletos." });
    }
    const { data: user, error } = await supabase
      .from("usuarios").select("domain, access_token").eq("domain", domain).single();
    if (error || !user || user.access_token !== token) {
      return res.status(401).json({ success: false, error: "No autorizado: token inválido." });
    }
    req.authenticatedDomain = user.domain;
    next();
  } catch (e) {
    res.status(500).json({ success: false, error: "Error interno de autenticación." });
  }
}

// ─── MIDDLEWARE: API KEY ──────────────────────────────────────────────────────
const requireAdminKey = (req, res, next) => {
  if (!process.env.ADMIN_SECRET || req.headers["x-api-key"] !== process.env.ADMIN_SECRET) {
    return res.status(401).json({ success: false, error: "No autorizado." });
  }
  next();
};

// ─── HELPERS DE MÉTRICAS ─────────────────────────────────────────────────────
function generarRangoDias(desdeISO, cantidad) {
  const dias = [];
  const base = new Date(desdeISO + "T12:00:00");
  for (let i = 0; i < cantidad; i++) {
    const d = new Date(base);
    d.setDate(base.getDate() + i);
    dias.push(d.toISOString().split("T")[0]);
  }
  return dias;
}

function agruparVentas(ventas, hoyISO) {
  const porDia    = {};
  const porSemana = {};
  const porMes    = {};
  const porEstado = { aprobado: 0, pendiente: 0, rechazado: 0 };
  const clientesSet = new Set();
  let volumenTotal = 0, cantidadTotal = 0;

  ventas.forEach((v) => {
    const fecha  = (v.fecha_pago || v.created_at || hoyISO).split("T")[0];
    const monto  = Number(v.monto || 0);
    const estado = v.estado || "aprobado";
    const [va, vm, vd] = fecha.split("-").map(Number);
    const semKey = `${va}-S${Math.ceil(vd / 7)}`;
    const mesKey = `${va}-${String(vm).padStart(2, "0")}`;

    // Por día
    if (!porDia[fecha]) porDia[fecha] = { volumen: 0, cantidad: 0, aprobado: 0, pendiente: 0, rechazado: 0 };
    porDia[fecha].volumen  += monto;
    porDia[fecha].cantidad += 1;
    porDia[fecha][estado]  = (porDia[fecha][estado] || 0) + 1;

    // Por semana
    if (!porSemana[semKey]) porSemana[semKey] = { label: semKey, volumen: 0, cantidad: 0 };
    porSemana[semKey].volumen  += monto;
    porSemana[semKey].cantidad += 1;

    // Por mes
    if (!porMes[mesKey]) porMes[mesKey] = { label: mesKey, volumen: 0, cantidad: 0 };
    porMes[mesKey].volumen  += monto;
    porMes[mesKey].cantidad += 1;

    // Estado global
    porEstado[estado] = (porEstado[estado] || 0) + 1;

    // Clientes únicos
    if (v.email_cliente) clientesSet.add(v.email_cliente.toLowerCase());
    else if (v.telefono_cliente) clientesSet.add(v.telefono_cliente);

    // Totales solo aprobados
    if (estado === "aprobado") { volumenTotal += monto; cantidadTotal += 1; }
  });

  return {
    porDia,
    porSemana:      Object.values(porSemana).sort((a, b) => a.label.localeCompare(b.label)),
    porMes:         Object.values(porMes).sort((a, b) => a.label.localeCompare(b.label)),
    porEstado,
    volumenTotal,
    cantidadTotal,
    ticketPromedio: cantidadTotal > 0 ? Math.round(volumenTotal / cantidadTotal) : 0,
    clientesNuevos: clientesSet.size,
  };
}

// ─── RUTA RAÍZ ───────────────────────────────────────────────────────────────
app.get("/", (req, res) => res.json({ status: "online", message: "NegoSocio API v3.0", timestamp: new Date().toISOString() }));
app.get("/health", (req, res) => res.json({ status: "ok", timestamp: new Date().toISOString() }));

// ═══════════════════════════════════════════════════════════════════════════════
// ADMIN: CREAR CLIENTE
// ═══════════════════════════════════════════════════════════════════════════════

// POST /admin/crear-cliente
// Headers: { "x-api-key": ADMIN_SECRET }
// Body: { business_name, domain, slug, email, password, nombre_persona?, precio?, duracion_turno?, telefono? }
app.post("/admin/crear-cliente", requireAdminKey, async (req, res) => {
  try {
    const { business_name, domain, slug, email, password, nombre_persona, precio, duracion_turno, telefono } = req.body;

    if (!business_name || !domain || !slug || !email || !password) {
      return res.status(400).json({ success: false, error: "Faltan campos: business_name, domain, slug, email, password." });
    }

    const cleanDomain = getCleanDomain(domain);
    const cleanSlug   = getCleanSlug(slug);

    if (!validateDomain(cleanDomain)) return res.status(400).json({ success: false, error: "Domain inválido. Ej: barberiajuan.com" });
    if (!validateEmail(email))         return res.status(400).json({ success: false, error: "Email inválido." });

    const hashedPassword = await bcrypt.hash(String(password), BCRYPT_ROUNDS);

    const { data, error } = await supabase.from("usuarios").insert([{
      business_name:  business_name.trim(),
      domain:         cleanDomain,
      slug:           cleanSlug,
      email:          email.trim().toLowerCase(),
      password:       hashedPassword,
      nombre_persona: nombre_persona?.trim() || "Dueño",
      precio:         parseInt(precio) || 0,
      duracion_turno: parseInt(duracion_turno) || 30,
      telefono:       telefono || null,
      metodo_pago:    "none",
      excepciones:    [],
    }]).select().single();

    if (error) {
      if (error.code === "23505") return res.status(409).json({ success: false, error: "El domain, slug o email ya existe." });
      throw error;
    }

    console.log(`Cliente creado: ${cleanDomain} (slug: ${cleanSlug})`);
    res.status(201).json({ success: true, domain: cleanDomain, slug: cleanSlug });
  } catch (e) {
    console.error("Error en /admin/crear-cliente:", e.message);
    res.status(500).json({ success: false, error: e.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// AUTH
// ═══════════════════════════════════════════════════════════════════════════════

// POST /login — Body: { slug, password }
app.post("/login", limiterAuth, async (req, res) => {
  try {
    const slug     = getCleanSlug(req.body.slug);
    const password = req.body.password;

    if (!slug || !password) return res.status(400).json({ success: false, error: "Faltan slug o contraseña." });

    const { data: user, error } = await supabase.from("usuarios").select("*").eq("slug", slug).single();
    if (error || !user) return res.status(401).json({ success: false, error: "Credenciales incorrectas." });

    let passwordOk = false;
    const isHashed = user.password?.startsWith("$2b$") || user.password?.startsWith("$2a$");
    if (isHashed) {
      passwordOk = await bcrypt.compare(String(password), user.password);
    } else {
      passwordOk = String(user.password) === String(password);
      if (passwordOk) {
        const newHash = await bcrypt.hash(String(password), BCRYPT_ROUNDS);
        await supabase.from("usuarios").update({ password: newHash }).eq("slug", slug);
      }
    }

    if (!passwordOk) return res.status(401).json({ success: false, error: "Credenciales incorrectas." });

    const newAccessToken = crypto.randomBytes(32).toString("hex");
    await supabase.from("usuarios").update({ access_token: newAccessToken }).eq("slug", slug);

    res.json({ success: true, domain: user.domain, slug: user.slug, access_token: newAccessToken, business_name: user.business_name, email: user.email });
  } catch (e) {
    console.error("Error en /login:", e.message);
    res.status(500).json({ success: false, error: e.message });
  }
});

// GET /verify-session?domain=...
// Headers: { Authorization: "Bearer <token>" }
app.get("/verify-session", async (req, res) => {
  try {
    const token  = req.headers["authorization"]?.split(" ")[1];
    const domain = getCleanDomain(req.query.domain || "");
    if (!token || !domain) return res.json({ active: false, reason: "missing_params" });

    const { data: user, error } = await supabase
      .from("usuarios").select("slug, domain, access_token, business_name, email").eq("domain", domain).single();

    if (error || !user) return res.json({ active: false, reason: "user_not_found" });
    if (!user.access_token || user.access_token !== token) return res.json({ active: false, reason: "invalid_token" });

    res.json({ active: true, slug: user.slug, domain: user.domain, business_name: user.business_name, email: user.email });
  } catch (e) {
    res.status(500).json({ active: false, error: e.message });
  }
});

// POST /api/request-password-reset — Body: { email, newPassword }
app.post("/api/request-password-reset", limiterAuth, async (req, res) => {
  try {
    const { email, newPassword } = req.body;
    if (!email || !newPassword) return res.status(400).json({ success: false, error: "Faltan datos." });
    if (!validatePassword(newPassword)) return res.status(400).json({ success: false, error: "Mínimo 6 caracteres." });

    const { data: user } = await supabase.from("usuarios").select("domain").eq("email", email.trim().toLowerCase()).single();
    if (!user) return res.json({ success: true });

    const googleRes = await fetch(APPS_SCRIPT_URL, {
      method: "POST", headers: { "Content-Type": "text/plain" },
      body: JSON.stringify({ action: "resetPassword", email: email.trim().toLowerCase(), newPassword }),
    });
    const text   = await googleRes.text();
    const result = JSON.parse(text.substring(text.indexOf("{"), text.lastIndexOf("}") + 1));
    res.json(result.status === "success" ? { success: true } : { success: false, error: result.message });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// POST /api/verify-and-reset-password — Body: { email, code }
app.post("/api/verify-and-reset-password", limiterAuth, async (req, res) => {
  try {
    const { email, code } = req.body;
    if (!email || !code) return res.status(400).json({ success: false, error: "Faltan datos." });

    const googleRes = await fetch(APPS_SCRIPT_URL, {
      method: "POST", headers: { "Content-Type": "text/plain" },
      body: JSON.stringify({ action: "verifyCode", email: email.trim().toLowerCase(), code: code.toString().trim() }),
    });
    const result = await googleRes.json();
    if (result.status !== "valid") return res.status(400).json({ success: false, error: "Código incorrecto o expirado." });

    const hashedPassword = await bcrypt.hash(String(result.password), BCRYPT_ROUNDS);
    const { error } = await supabase.from("usuarios").update({ password: hashedPassword }).eq("email", email.trim().toLowerCase());
    if (error) throw error;
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// PAGOS
// ═══════════════════════════════════════════════════════════════════════════════

// POST /api/create-preference
// Body: { nombre, telefono, email, fecha, hora, domain, servicio_id? }
app.post("/api/create-preference", limiterBooking, async (req, res) => {
  try {
    const { nombre, telefono, email, fecha, hora, domain, servicio_id } = req.body;
    if (!nombre || !telefono || !fecha || !hora || !domain) {
      return res.status(400).json({ success: false, error: "Faltan datos requeridos." });
    }
    if (email && !validateEmail(email)) return res.status(400).json({ success: false, error: "Email inválido." });

    const cleanDomain = getCleanDomain(domain);
    const { data: user, error: userError } = await supabase.from("usuarios").select("*").eq("domain", cleanDomain).single();
    if (userError || !user) return res.status(404).json({ success: false, error: "Negocio no encontrado." });

    let precioFinal    = Number(user.precio || 0);
    let nombreServicio = "Reserva";
    let servicioNombre = null;

    if (servicio_id) {
      const { data: srv } = await supabase.from("servicios").select("*").eq("id", servicio_id).eq("domain", cleanDomain).single();
      if (srv) { precioFinal = Number(srv.precio || precioFinal); nombreServicio = srv.nombre; servicioNombre = srv.nombre; }
    }

    if (user.metodo_pago === "sena" && user.monto_sena) precioFinal = Number(user.monto_sena);

    const metodo    = user.metodo_pago || "none";
    const debePagar = metodo === "sena" || metodo === "total";
    if (!debePagar || precioFinal <= 0) return res.json({ isFree: true });

    const conceptoPago = metodo === "sena" ? "Seña" : "Total";
    const successUrl   = `https://${cleanDomain}/success`;
    const cancelUrl    = `https://${cleanDomain}/error`;
    const metaMeta     = { nombre, telefono, email: email || "", fecha, hora, domain: cleanDomain, servicio_id: servicio_id || "", servicio_nombre: servicioNombre || "", metodo_pago: metodo };

    // ── Stripe ──
    if (user.stripe_secret_key) {
      try {
        const stripe  = new Stripe(user.stripe_secret_key);
        const session = await stripe.checkout.sessions.create({
          payment_method_types: ["card"],
          line_items: [{ price_data: { currency: "ars", product_data: { name: `${nombreServicio} (${conceptoPago}): ${fecha} a las ${hora}hs` }, unit_amount: Math.round(precioFinal * 100) }, quantity: 1 }],
          mode: "payment",
          metadata: metaMeta,
          success_url: successUrl,
          cancel_url:  cancelUrl,
        });
        return res.json({ payment_url: session.url });
      } catch (e) {
        return res.status(500).json({ success: false, error: "Error con Stripe." });
      }
    }

    // ── Mercado Pago ──
    if (user.mp_access_token) {
      try {
        const client   = new MercadoPagoConfig({ accessToken: user.mp_access_token });
        const pref     = new Preference(client);
        const response = await pref.create({
          body: {
            items: [{ title: `${nombreServicio} (${conceptoPago}): ${fecha} - ${hora}hs`, unit_price: precioFinal, quantity: 1, currency_id: "ARS" }],
            metadata: { ...metaMeta, tipo_pago: metodo },
            notification_url: "https://framerturnero.onrender.com/webhook",
            back_urls: { success: successUrl, failure: cancelUrl, pending: cancelUrl },
            auto_return: "approved",
          },
        });
        return res.json({ payment_url: response.init_point });
      } catch (e) {
        return res.status(500).json({ success: false, error: "Error con MercadoPago." });
      }
    }

    return res.status(400).json({ success: false, error: "Sin método de pago configurado." });
  } catch (e) {
    console.error("Error en /api/create-preference:", e.message);
    res.status(500).json({ success: false, error: e.message });
  }
});

// GET /oauth-callback?code=...&state=domain
app.get("/oauth-callback", async (req, res) => {
  const { code, state: domain } = req.query;
  if (!code || !domain) return res.status(400).send("Parámetros inválidos.");
  try {
    const cleanDomain = getCleanDomain(domain);
    if (!validateDomain(cleanDomain)) return res.status(400).send("Domain inválido.");

    const response = await fetch("https://api.mercadopago.com/oauth/token", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ client_id: process.env.MP_TURNERO_CLIENT_ID, client_secret: process.env.MP_TURNERO_CLIENT_SECRET, grant_type: "authorization_code", code, redirect_uri: "https://framerturnero.onrender.com/oauth-callback" }),
    });
    const data = await response.json();
    if (data.access_token) {
      await supabase.from("usuarios").update({ mp_access_token: data.access_token }).eq("domain", cleanDomain);
      return res.redirect(`https://${cleanDomain}/panel?status=mp_success`);
    }
    res.redirect(`https://${cleanDomain}/panel?status=mp_error`);
  } catch (e) {
    res.status(500).send("Error al vincular.");
  }
});

// POST /webhook — MP notifica pagos. Guarda turno + venta en Supabase.
app.post("/webhook", async (req, res) => {
  const { query, body } = req;
  try {
    if (query.topic === "payment" || body.type === "payment") {
      const paymentId = query.id || body.data?.id;
      if (!paymentId) return res.sendStatus(200);

      const payRes  = await fetch(`https://api.mercadopago.com/v1/payments/${paymentId}`, { headers: { Authorization: `Bearer ${process.env.MP_ACCESS_TOKEN}` } });
      const payData = await payRes.json();

      if (!payData.metadata?.domain) return res.sendStatus(200);

      const domain = getCleanDomain(payData.metadata.domain);
      const { data: userNegocio } = await supabase.from("usuarios").select("mp_access_token, email").eq("domain", domain).single();

      // Re-consultar con el token real del negocio para metadata completa
      let meta = payData.metadata;
      if (userNegocio?.mp_access_token) {
        const real = await fetch(`https://api.mercadopago.com/v1/payments/${paymentId}`, { headers: { Authorization: `Bearer ${userNegocio.mp_access_token}` } });
        meta = (await real.json()).metadata;
      }

      const { nombre, telefono, email, fecha, hora, servicio_id, servicio_nombre } = meta;
      const monto  = Number(payData.transaction_amount || 0);
      const moneda = payData.currency_id || "ARS";
      const estado = payData.status === "approved" ? "aprobado" : payData.status === "pending" ? "pendiente" : "rechazado";

      // ── Insertar turno en Supabase (solo si es aprobado) ──
      let turnoId = null;
      if (payData.status === "approved") {
        const { data: turnoInsertado } = await supabase.from("turnos").insert([{
          domain,
          nombre:          nombre?.trim() || "Cliente",
          telefono:        telefono?.toString().trim() || "N/A",
          email:           email?.trim() || null,
          fecha,
          hora,
          servicio_id:     servicio_id || null,
          servicio_nombre: servicio_nombre || null,
          estado:          "confirmado",
          metodo_pago:     "mercadopago",
          payment_id:      String(paymentId),
        }]).select().single();

        turnoId = turnoInsertado?.id || null;

        // Mail al negocio y al cliente
        if (userNegocio?.email) {
          fetch(APPS_SCRIPT_URL, {
            method: "POST", headers: { "Content-Type": "text/plain" },
            body: JSON.stringify({ action: "newAppointmentEmail", nombreCliente: nombre?.trim() || "Cliente", fechaHora: `${fecha} ${hora}`, adminEmail: userNegocio.email, emailCliente: email?.trim() || "" }),
          }).catch((e) => console.error("Error mail webhook:", e.message));
        }
      }

      // ── Insertar venta en Supabase (todos los estados) ──
      await supabase.from("ventas").insert([{
        domain,
        turno_id:         turnoId,
        fecha_turno:      fecha,
        fecha_pago:       new Date().toISOString(),
        monto,
        moneda,
        metodo_pago:      "mercadopago",
        estado,
        nombre_cliente:   nombre?.trim() || "Cliente",
        email_cliente:    email?.trim() || null,
        telefono_cliente: telefono?.toString().trim() || null,
        servicio_id:      servicio_id || null,
        servicio_nombre:  servicio_nombre || null,
        payment_id:       String(paymentId),
      }]);

      delete globalCache[domain];
      console.log(`Webhook procesado: ${domain} — ${estado} — $${monto} ${moneda}`);
    }
    res.sendStatus(200);
  } catch (e) {
    console.error("Error en webhook:", e.message);
    res.sendStatus(200);
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// TURNOS — todo desde Supabase
// ═══════════════════════════════════════════════════════════════════════════════

// GET /get-occupied?domain=...&fecha=YYYY-MM-DD
// Devuelve los turnos ocupados de un día específico
app.get("/get-occupied", async (req, res) => {
  try {
    const domain = getCleanDomain(req.query.domain);
    const { fecha } = req.query;

    if (!validateDomain(domain)) return res.status(400).json({ success: false, error: "Domain inválido." });

    const query = supabase.from("turnos").select("hora").eq("domain", domain).neq("estado", "cancelado");
    if (fecha) query.eq("fecha", fecha);

    const { data, error } = await query;
    if (error) throw error;

    const ocupados = (data || []).map((t) => t.hora.slice(0, 5)); // "HH:MM"
    res.json({ success: true, ocupados });
  } catch (e) {
    console.error("Error en /get-occupied:", e.message);
    res.status(500).json({ success: false, error: e.message });
  }
});

// POST /create-booking — Body: { name, phone, email?, fecha, hora, domain, servicio_id? }
app.post("/create-booking", limiterBooking, async (req, res) => {
  try {
    const { name, phone, email, fecha, hora, domain, servicio_id } = req.body;

    if (!name || !phone || !fecha || !hora || !domain) {
      return res.status(400).json({ success: false, error: "Faltan datos requeridos." });
    }
    if (!validatePhone(phone.toString())) return res.status(400).json({ success: false, error: "Teléfono inválido." });

    const cleanDomain = getCleanDomain(domain);
    if (!validateDomain(cleanDomain)) return res.status(400).json({ success: false, error: "Domain inválido." });

    const { data: user, error: userError } = await supabase.from("usuarios").select("*").eq("domain", cleanDomain).single();
    if (userError || !user) return res.status(404).json({ success: false, error: "Negocio no encontrado." });

    const requierePago = user.mp_access_token && (user.metodo_pago === "sena" || user.metodo_pago === "total");
    if (requierePago) return res.status(403).json({ success: false, error: "Este turno requiere pago previo." });

    // Anti-duplicado: verificar si el cliente ya tiene turno futuro activo
    const hoy = new Date().toISOString().split("T")[0];
    const { data: turnosExistentes } = await supabase
      .from("turnos")
      .select("id")
      .eq("domain", cleanDomain)
      .gte("fecha", hoy)
      .neq("estado", "cancelado")
      .or(`telefono.eq.${phone.toString().trim()}${email ? `,email.eq.${email.trim().toLowerCase()}` : ""}`);

    if (turnosExistentes && turnosExistentes.length > 0) {
      return res.status(400).json({ success: false, error: "Ya tenés un turno agendado activo." });
    }

    // Verificar que el slot no esté lleno
    const { data: user2 } = await supabase.from("usuarios").select("capacidad_por_turno").eq("domain", cleanDomain).single();
    const capacidad = user2?.capacidad_por_turno || 1;

    const { count } = await supabase.from("turnos")
      .select("id", { count: "exact" })
      .eq("domain", cleanDomain).eq("fecha", fecha).eq("hora", hora).neq("estado", "cancelado");

    if (count >= capacidad) {
      return res.status(400).json({ success: false, error: "Este turno ya está lleno." });
    }

    // Guardar turno
    let servicioNombre = null;
    if (servicio_id) {
      const { data: srv } = await supabase.from("servicios").select("nombre").eq("id", servicio_id).single();
      servicioNombre = srv?.nombre || null;
    }

    const { data: turno, error: turnoError } = await supabase.from("turnos").insert([{
      domain:          cleanDomain,
      nombre:          name.trim(),
      telefono:        phone.toString().trim(),
      email:           email?.trim() || null,
      fecha,
      hora,
      servicio_id:     servicio_id || null,
      servicio_nombre: servicioNombre,
      estado:          "pendiente",
      metodo_pago:     "none",
    }]).select().single();

    if (turnoError) throw turnoError;

    // Mail al negocio
    fetch(APPS_SCRIPT_URL, {
      method: "POST", headers: { "Content-Type": "text/plain" },
      body: JSON.stringify({ action: "newAppointmentEmail", nombreCliente: name.trim(), fechaHora: `${fecha} ${hora}`, adminEmail: user.email, emailCliente: email?.trim() || "" }),
    }).catch((e) => console.error("Error mail booking:", e.message));

    delete globalCache[cleanDomain];
    res.json({ success: true, turno_id: turno.id, message: "Turno creado con éxito." });
  } catch (e) {
    console.error("Error en /create-booking:", e.message);
    res.status(500).json({ success: false, error: e.message });
  }
});

// POST /cancel-appointment (protegido) — Body: { domain, turno_id }
app.post("/cancel-appointment", requireAuth, async (req, res) => {
  try {
    const { domain, turno_id } = req.body;
    const cleanDomain = getCleanDomain(domain);

    if (!turno_id) return res.status(400).json({ success: false, error: "Falta el turno_id." });

    const { error } = await supabase.from("turnos")
      .update({ estado: "cancelado" })
      .eq("id", turno_id)
      .eq("domain", cleanDomain);

    if (error) throw error;
    delete globalCache[cleanDomain];
    res.json({ success: true, message: "Turno cancelado." });
  } catch (e) {
    console.error("Error en /cancel-appointment:", e.message);
    res.status(500).json({ success: false, error: e.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// SLOTS DISPONIBLES
// ═══════════════════════════════════════════════════════════════════════════════

// GET /slots-disponibles/:domain?fecha=YYYY-MM-DD&servicio_id=...
app.get("/slots-disponibles/:domain", async (req, res) => {
  try {
    const domain = getCleanDomain(req.params.domain);
    const { fecha, servicio_id } = req.query;

    if (!validateDomain(domain)) return res.status(400).json({ success: false, error: "Domain inválido." });

    const { data: user, error: userError } = await supabase
      .from("usuarios").select("horarios, duracion_turno, capacidad_por_turno, excepciones").eq("domain", domain).single();
    if (userError || !user) return res.status(404).json({ success: false, error: "Negocio no encontrado." });

    let duracion = user.duracion_turno || 30;
    let capacidad = user.capacidad_por_turno || 1;

    if (servicio_id) {
      const { data: srv } = await supabase.from("servicios").select("duracion, capacidad").eq("id", servicio_id).eq("domain", domain).single();
      if (srv) { duracion = srv.duracion || duracion; capacidad = srv.capacidad || capacidad; }
    }

    if (user.excepciones?.includes(fecha)) return res.json({ success: true, slots: [] });

    const diasSemana = ["domingo", "lunes", "martes", "miercoles", "jueves", "viernes", "sabado"];
    const diaConfig  = user.horarios?.[diasSemana[new Date(fecha + "T12:00:00").getDay()]];
    if (!diaConfig?.activo) return res.json({ success: true, slots: [] });

    const toMin   = (t) => { if (!t) return null; const [h, m] = t.split(":").map(Number); return h * 60 + m; };
    const fromMin = (m) => `${Math.floor(m / 60).toString().padStart(2, "0")}:${(m % 60).toString().padStart(2, "0")}`;

    const inicio = toMin(diaConfig.jornada[0]);
    const fin    = toMin(diaConfig.jornada[1]);
    const dIni   = toMin(diaConfig.descanso?.[0]);
    const dFin   = toMin(diaConfig.descanso?.[1]);

    const slotsGenerados = [];
    let cursor = inicio;
    while (cursor + duracion <= fin) {
      if (!(dIni && dFin && cursor >= dIni && cursor < dFin)) slotsGenerados.push(fromMin(cursor));
      cursor += duracion;
    }

    // Contar reservas por slot desde Supabase
    const { data: turnosDia } = await supabase
      .from("turnos").select("hora")
      .eq("domain", domain).eq("fecha", fecha).neq("estado", "cancelado");

    const reservasPorSlot = {};
    (turnosDia || []).forEach((t) => {
      const h = t.hora.slice(0, 5);
      reservasPorSlot[h] = (reservasPorSlot[h] || 0) + 1;
    });

    const slots = slotsGenerados.map((slot) => {
      const reservados  = reservasPorSlot[slot] || 0;
      const disponibles = capacidad - reservados;
      return { hora: slot, disponibles: Math.max(0, disponibles), lleno: disponibles <= 0 };
    });

    res.json({ success: true, slots });
  } catch (e) {
    console.error("Error en /slots-disponibles:", e.message);
    res.status(500).json({ success: false, error: e.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// SERVICIOS
// ═══════════════════════════════════════════════════════════════════════════════

// GET /servicios/:domain — activos (web pública)
app.get("/servicios/:domain", async (req, res) => {
  try {
    const domain = getCleanDomain(req.params.domain);
    if (!validateDomain(domain)) return res.status(400).json({ success: false, error: "Domain inválido." });
    const { data, error } = await supabase
      .from("servicios").select("id, nombre, descripcion, duracion, precio, capacidad")
      .eq("domain", domain).eq("activo", true).order("created_at", { ascending: true });
    if (error) throw error;
    res.json({ success: true, servicios: data || [] });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// GET /servicios/admin/:domain — todos (panel, protegido)
app.get("/servicios/admin/:domain", async (req, res) => {
  try {
    const token  = req.headers["authorization"]?.split(" ")[1];
    const domain = getCleanDomain(req.params.domain);
    if (!token || !domain) return res.status(401).json({ success: false, error: "No autorizado." });

    const { data: user } = await supabase.from("usuarios").select("access_token").eq("domain", domain).single();
    if (!user || user.access_token !== token) return res.status(401).json({ success: false, error: "No autorizado." });

    const { data, error } = await supabase.from("servicios").select("*").eq("domain", domain).order("created_at", { ascending: true });
    if (error) throw error;
    res.json({ success: true, servicios: data || [] });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// POST /servicios/crear (protegido) — Body: { domain, nombre, descripcion?, duracion, precio, capacidad? }
app.post("/servicios/crear", requireAuth, async (req, res) => {
  try {
    const { domain, nombre, descripcion, duracion, precio, capacidad } = req.body;
    const cleanDomain = getCleanDomain(domain);
    if (!cleanDomain || !nombre || !duracion || precio === undefined) {
      return res.status(400).json({ success: false, error: "Faltan campos." });
    }
    const { data, error } = await supabase.from("servicios").insert([{
      domain: cleanDomain, nombre: nombre.trim(), descripcion: descripcion?.trim() || "",
      duracion: parseInt(duracion), precio: Number(precio), capacidad: parseInt(capacidad) || 1, activo: true,
    }]).select().single();
    if (error) throw error;
    delete globalCache[cleanDomain];
    res.status(201).json({ success: true, servicio: data });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// POST /servicios/editar (protegido) — Body: { domain, id, ...campos? }
app.post("/servicios/editar", requireAuth, async (req, res) => {
  try {
    const { id, domain, nombre, descripcion, duracion, precio, capacidad, activo } = req.body;
    const cleanDomain = getCleanDomain(domain);
    if (!id) return res.status(400).json({ success: false, error: "Falta el id." });

    const u = {};
    if (nombre      !== undefined) u.nombre      = nombre.trim();
    if (descripcion !== undefined) u.descripcion = descripcion.trim();
    if (duracion    !== undefined) u.duracion    = parseInt(duracion);
    if (precio      !== undefined) u.precio      = Number(precio);
    if (capacidad   !== undefined) u.capacidad   = parseInt(capacidad);
    if (activo      !== undefined) u.activo      = activo;

    const { data, error } = await supabase.from("servicios").update(u).eq("id", id).eq("domain", cleanDomain).select().single();
    if (error) throw error;
    delete globalCache[cleanDomain];
    res.json({ success: true, servicio: data });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// POST /servicios/eliminar (protegido) — Body: { domain, id }
app.post("/servicios/eliminar", requireAuth, async (req, res) => {
  try {
    const { id, domain } = req.body;
    if (!id) return res.status(400).json({ success: false, error: "Falta el id." });
    const { error } = await supabase.from("servicios").delete().eq("id", id).eq("domain", getCleanDomain(domain));
    if (error) throw error;
    delete globalCache[getCleanDomain(domain)];
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// ADMIN STATS
// ═══════════════════════════════════════════════════════════════════════════════

// GET /admin-stats/:domain (protegido)
// Headers: { Authorization: "Bearer <token>" }
app.get("/admin-stats/:domain", async (req, res) => {
  const token  = req.headers["authorization"]?.split(" ")[1];
  const domain = getCleanDomain(req.params.domain);

  if (!token || !domain) return res.status(401).json({ success: false, error: "No autorizado." });

  const { data: authUser } = await supabase.from("usuarios").select("access_token").eq("domain", domain).single();
  if (!authUser || authUser.access_token !== token) return res.status(401).json({ success: false, error: "No autorizado." });

  const now = Date.now();
  if (globalCache[domain] && now - globalCache[domain].timestamp < CACHE_DURATION) {
    return res.json(globalCache[domain].data);
  }

  try {
    const { data: user, error: userError } = await supabase.from("usuarios").select("*").eq("domain", domain).single();
    if (userError || !user) return res.status(404).json({ success: false, error: "Usuario no encontrado." });

    // Fecha actual Argentina
    const ahoraArg   = new Date(new Date().toLocaleString("en-US", { timeZone: "America/Argentina/Buenos_Aires" }));
    const anioActual = ahoraArg.getFullYear();
    const mesActual  = ahoraArg.getMonth() + 1;
    const diaHoyNum  = ahoraArg.getDate();
    const hoyISO     = `${anioActual}-${String(mesActual).padStart(2, "0")}-${String(diaHoyNum).padStart(2, "0")}`;

    // ── Turnos desde Supabase ──
    const inicioMes = `${anioActual}-${String(mesActual).padStart(2, "0")}-01`;
    const { data: turnosMes } = await supabase
      .from("turnos").select("*")
      .eq("domain", domain)
      .gte("fecha", inicioMes)
      .neq("estado", "cancelado")
      .order("fecha", { ascending: true });

    const turnosData    = turnosMes || [];
    const turnosHoy     = turnosData.filter((t) => t.fecha === hoyISO).length;
    const turnosMesTotal = turnosData.length;

    // Chart semanal
    const semanas = { "Sem 1": 0, "Sem 2": 0, "Sem 3": 0, "Sem 4": 0 };
    turnosData.forEach((t) => {
      const dia = parseInt(t.fecha.split("-")[2]);
      let sem = "Sem 1";
      if (dia > 7 && dia <= 14) sem = "Sem 2";
      else if (dia > 14 && dia <= 21) sem = "Sem 3";
      else if (dia > 21) sem = "Sem 4";
      semanas[sem]++;
    });

    // Lista de turnos para el panel
    const turnosLista = turnosData.map((t) => ({
      id:       t.id,
      nombre:   t.nombre,
      telefono: t.telefono,
      email:    t.email,
      fecha:    t.fecha,
      hora:     t.hora.slice(0, 5),
      servicio: t.servicio_nombre,
      estado:   t.estado,
      duracion: user.duracion_turno || 60,
    })).reverse();

    // ── Ventas desde Supabase (90 días + proyección 7 días) ──
    const desde90 = new Date(ahoraArg);
    desde90.setDate(desde90.getDate() - 90);
    const desde90ISO = desde90.toISOString().split("T")[0];

    const hasta7 = new Date(ahoraArg);
    hasta7.setDate(hasta7.getDate() + 7);
    const hasta7ISO = hasta7.toISOString().split("T")[0];

    const { data: ventas } = await supabase
      .from("ventas").select("*")
      .eq("domain", domain)
      .gte("fecha_turno", desde90ISO)
      .lte("fecha_turno", hasta7ISO)
      .order("fecha_pago", { ascending: true });

    const metricas = agruparVentas(ventas || [], hoyISO);

    const mesKey        = `${anioActual}-${String(mesActual).padStart(2, "0")}`;
    const ventasHoy     = metricas.porDia[hoyISO] || { volumen: 0, cantidad: 0, aprobado: 0, pendiente: 0, rechazado: 0 };
    const ventasMes     = metricas.porMes.find((m) => m.label === mesKey) || { volumen: 0, cantidad: 0 };
    const proximosDias  = generarRangoDias(hoyISO, 7).map((fecha) => ({
      fecha,
      ...(metricas.porDia[fecha] || { volumen: 0, cantidad: 0, aprobado: 0, pendiente: 0, rechazado: 0 }),
    }));

    const finalData = {
      stats: {
        nombre_persona: user.nombre_persona,
        businessName:   user.business_name,

        // Turnos
        turnosHoy,
        turnosMes:      turnosMesTotal,
        chartData:      Object.keys(semanas).map((k) => ({ label: k, turnos: semanas[k] })),
        turnosLista,

        // Ventas — resumen
        ventas: {
          volumenTotal:   metricas.volumenTotal,
          volumenHoy:     ventasHoy.volumen,
          volumenMes:     ventasMes.volumen || 0,
          ticketPromedio: metricas.ticketPromedio,
          cantidadTotal:  metricas.cantidadTotal,
          cantidadHoy:    ventasHoy.cantidad,
          cantidadMes:    ventasMes.cantidad || 0,
          clientesNuevos: metricas.clientesNuevos,
          estados: {
            aprobado:  metricas.porEstado.aprobado  || 0,
            pendiente: metricas.porEstado.pendiente || 0,
            rechazado: metricas.porEstado.rechazado || 0,
          },
        },

        // Series para gráficos
        ventasPorDia:   metricas.porDia,
        ventasPorSem:   metricas.porSemana,
        ventasPorMes:   metricas.porMes,
        proximosDias,

        // Config
        horarios: user.horarios,
        config: {
          duracion:    user.duracion_turno,
          precio:      user.precio,
          monto_sena:  user.monto_sena  || 0,
          metodo_pago: user.metodo_pago || "none",
          mp_status:   user.mp_access_token ? "Conectado" : "Desconectado",
          excepciones: user.excepciones || [],
        },
      },
    };

    globalCache[domain] = { timestamp: now, data: finalData };
    res.json(finalData);
  } catch (e) {
    console.error("Error en /admin-stats:", e.message);
    res.status(500).json({ success: false, error: "Error al procesar estadísticas." });
  }
});

// POST /update-settings (protegido)
// Body: { domain, precio?, horarios?, duracion_turno?, ocupados?, monto_sena?, metodo_pago? }
app.post("/update-settings", requireAuth, async (req, res) => {
  try {
    const { domain, precio, horarios, duracion_turno, ocupados, monto_sena, metodo_pago } = req.body;
    const cleanDomain = getCleanDomain(domain);

    const numPrecio = parseInt(precio) || 0;
    const numSena   = parseInt(monto_sena) || 0;
    if (numPrecio < 0) return res.status(400).json({ success: false, error: "El precio no puede ser negativo." });

    const u = { precio: numPrecio, monto_sena: numSena, metodo_pago: metodo_pago || "none", duracion_turno: parseInt(duracion_turno) || 30 };
    if (horarios) u.horarios    = horarios;
    if (ocupados) u.excepciones = ocupados;

    const { error } = await supabase.from("usuarios").update(u).eq("domain", cleanDomain);
    if (error) throw error;
    delete globalCache[cleanDomain];
    res.json({ success: true, message: "Configuración actualizada." });
  } catch (e) {
    console.error("Error en /update-settings:", e.message);
    res.status(500).json({ success: false, error: e.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// 404 Y ERROR HANDLER
// ═══════════════════════════════════════════════════════════════════════════════

app.use("*", (req, res) => {
  res.status(404).json({ success: false, error: "Ruta no encontrada.", path: req.originalUrl });
});

app.use((err, req, res, next) => {
  console.error("Error no manejado:", err.message);
  res.status(500).json({ success: false, error: "Error interno del servidor." });
});

// ═══════════════════════════════════════════════════════════════════════════════
// ARRANQUE
// ═══════════════════════════════════════════════════════════════════════════════

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log(`
  ╔════════════════════════════════════════╗
  ║   NegoSocio API v3.0 — Online         ║
  ║   Sin Sheets — Todo en Supabase       ║
  ║   Puerto: ${PORT}                       ║
  ╚════════════════════════════════════════╝
  `);
});

export default app;
