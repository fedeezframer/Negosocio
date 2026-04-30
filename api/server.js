import express from "express";
import cors from "cors";
import { createClient } from "@supabase/supabase-js";
import { MercadoPagoConfig, Preference } from "mercadopago";
import fetch from "node-fetch";
import crypto from "crypto";
import bcrypt from "bcrypt";
import rateLimit from "express-rate-limit";

// ─── CONFIGURACIÓN GLOBAL ────────────────────────────────────────────────────
const app = express();

const APPS_SCRIPT_URL =
  "https://script.google.com/macros/s/AKfycbzvcaYhHuyD-Xu63Aw9WpWrpcr5xmrgHW_IffXkmC90bs0pTzhWP1d8rWBaBuhG5Icx/exec";

const BCRYPT_ROUNDS  = 10;
const CACHE_DURATION = 20000;  // ms
const PLATAFORMA_FEE = 0.025;  // 2.5% sobre precio total del servicio
const API_URL        = "https://negosocio.onrender.com";

// ─── VALIDADORES ─────────────────────────────────────────────────────────────
const getCleanSlug = (raw) => {
  if (!raw) return "";
  return raw.toLowerCase().trim()
    .normalize("NFD").replace(/[\u0300-\u036f]/g, "")
    .replace(/\s+/g, "-").replace(/[^a-z0-9-]/g, "");
};

const validateEmail    = (e) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);
const validatePassword = (p) => p && p.length >= 6;
// FIX: limpia espacios antes de validar (el InputData de Framer formatea con espacios)
const validatePhone    = (p) => /^[0-9]{7,15}$/.test(p.toString().replace(/\s/g, ""));
const cleanPhone       = (p) => p.toString().replace(/\s/g, "").trim();

// ─── CACHÉ (keyed por slug) ───────────────────────────────────────────────────
const globalCache = {};

// ─── RATE LIMITING ────────────────────────────────────────────────────────────
const limiterAuth    = rateLimit({ windowMs: 15 * 60 * 1000, max: 10, message: "Demasiados intentos.", standardHeaders: true, legacyHeaders: false });
const limiterBooking = rateLimit({ windowMs: 60 * 1000, max: 20, message: "Demasiadas reservas." });
const limiterAPI     = rateLimit({ windowMs: 60 * 1000, max: 200 });

// ─── CORS ─────────────────────────────────────────────────────────────────────
app.use(cors({ origin: "*", methods: ["GET", "POST", "OPTIONS"], allowedHeaders: ["Content-Type", "Authorization", "x-api-key"] }));
app.use(express.json({ limit: "10mb" }));
app.use(limiterAPI);

// ─── SUPABASE ─────────────────────────────────────────────────────────────────
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);

// ─── MIDDLEWARE: BEARER TOKEN ─────────────────────────────────────────────────
async function requireAuth(req, res, next) {
  try {
    const authHeader = req.headers["authorization"];
    if (!authHeader?.startsWith("Bearer ")) {
      return res.status(401).json({ success: false, error: "No autorizado: falta el token." });
    }
    const token = authHeader.split(" ")[1];
    const slug  = getCleanSlug(req.body?.slug || req.params?.slug || "");

    if (!token || !slug) {
      return res.status(401).json({ success: false, error: "No autorizado: datos incompletos." });
    }

    const { data: user, error } = await supabase
      .from("usuarios").select("slug, access_token").eq("slug", slug).single();

    if (error || !user || user.access_token !== token) {
      return res.status(401).json({ success: false, error: "No autorizado: token inválido." });
    }

    req.authenticatedSlug = user.slug;
    next();
  } catch (e) {
    res.status(500).json({ success: false, error: "Error interno de autenticación." });
  }
}

// ─── MIDDLEWARE: ADMIN KEY ────────────────────────────────────────────────────
const requireAdminKey = (req, res, next) => {
  if (!process.env.ADMIN_SECRET || req.headers["x-api-key"] !== process.env.ADMIN_SECRET) {
    return res.status(401).json({ success: false, error: "No autorizado." });
  }
  next();
};

// ─── HELPER: COMISIÓN ────────────────────────────────────────────────────────
// SIEMPRE sobre el precio total del servicio, nunca sobre la seña
function calcularServiceFee(precioTotalServicio) {
  return Math.round(Number(precioTotalServicio) * PLATAFORMA_FEE);
}

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

    if (!porDia[fecha]) porDia[fecha] = { volumen: 0, cantidad: 0, aprobado: 0, pendiente: 0, rechazado: 0 };
    porDia[fecha].volumen  += monto;
    porDia[fecha].cantidad += 1;
    porDia[fecha][estado]  = (porDia[fecha][estado] || 0) + 1;

    if (!porSemana[semKey]) porSemana[semKey] = { label: semKey, volumen: 0, cantidad: 0 };
    porSemana[semKey].volumen  += monto;
    porSemana[semKey].cantidad += 1;

    if (!porMes[mesKey]) porMes[mesKey] = { label: mesKey, volumen: 0, cantidad: 0 };
    porMes[mesKey].volumen  += monto;
    porMes[mesKey].cantidad += 1;

    porEstado[estado] = (porEstado[estado] || 0) + 1;

    if (v.email_cliente) clientesSet.add(v.email_cliente.toLowerCase());
    else if (v.telefono_cliente) clientesSet.add(v.telefono_cliente);

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

// ═══════════════════════════════════════════════════════════════════════════════
// RUTAS BASE
// ═══════════════════════════════════════════════════════════════════════════════

app.get("/", (req, res) => res.json({ status: "online", message: "NegoSocio API v4.1", timestamp: new Date().toISOString() }));
app.get("/health", (req, res) => res.json({ status: "ok", timestamp: new Date().toISOString() }));

// ─── NUEVO: Endpoint público para BookingTrigger ──────────────────────────────
// GET /negocio/:slug
// Sin token. Devuelve solo lo necesario para decidir si cobrar o no.
// No expone tokens ni datos sensibles, solo booleanos y config de precios.
app.get("/negocio/:slug", async (req, res) => {
  try {
    const slug = getCleanSlug(req.params.slug);
    if (!slug) return res.status(400).json({ success: false, error: "Slug inválido." });

    const { data: user, error } = await supabase
      .from("usuarios")
      .select("slug, business_name, precio, monto_sena, duracion_turno, metodo_pago, mp_access_token, mobbex_api_key, horarios, excepciones, capacidad_por_turno")
      .eq("slug", slug)
      .single();

    if (error || !user) return res.status(404).json({ success: false, error: "Negocio no encontrado." });

    res.json({
      success: true,
      negocio: {
        slug:           user.slug,
        business_name:  user.business_name,
        precio:         user.precio,
        monto_sena:     user.monto_sena || 0,
        duracion_turno: user.duracion_turno,
        metodo_pago:    user.metodo_pago || "none",
        tiene_mp:       !!user.mp_access_token,
        tiene_mobbex:   !!user.mobbex_api_key,
        horarios:       user.horarios,
        excepciones:    user.excepciones || [],
        capacidad:      user.capacidad_por_turno || 1,
        // Fee pre-calculado para mostrar en el front sin hacer math
        service_fee:    calcularServiceFee(user.precio || 0),
      },
    });
  } catch (e) {
    console.error("Error en /negocio/:slug:", e.message);
    res.status(500).json({ success: false, error: e.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// ADMIN: CREAR CLIENTE
// ═══════════════════════════════════════════════════════════════════════════════

// POST /admin/crear-cliente
// Headers: { "x-api-key": ADMIN_SECRET }
// Body: { business_name, slug, email, password, nombre_persona?, precio?, duracion_turno?, telefono? }
app.post("/admin/crear-cliente", requireAdminKey, async (req, res) => {
  try {
    const { business_name, slug, email, password, nombre_persona, precio, duracion_turno, telefono } = req.body;

    if (!business_name || !slug || !email || !password) {
      return res.status(400).json({ success: false, error: "Faltan campos: business_name, slug, email, password." });
    }
    if (!validateEmail(email))       return res.status(400).json({ success: false, error: "Email inválido." });
    if (!validatePassword(password)) return res.status(400).json({ success: false, error: "Contraseña muy corta (mínimo 6 caracteres)." });

    const cleanSlug      = getCleanSlug(slug);
    const hashedPassword = await bcrypt.hash(String(password), BCRYPT_ROUNDS);

    const { data, error } = await supabase.from("usuarios").insert([{
      business_name:  business_name.trim(),
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
      if (error.code === "23505") return res.status(409).json({ success: false, error: "El slug o email ya existe." });
      throw error;
    }

    console.log(`✅ Cliente creado: ${cleanSlug}`);
    res.status(201).json({ success: true, slug: cleanSlug, agenda_url: `${API_URL}/agenda?u=${cleanSlug}` });
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
      // Fallback para contraseñas viejas en texto plano — se migran al vuelo
      passwordOk = String(user.password) === String(password);
      if (passwordOk) {
        const newHash = await bcrypt.hash(String(password), BCRYPT_ROUNDS);
        await supabase.from("usuarios").update({ password: newHash }).eq("slug", slug);
        console.log(`🔐 Contraseña migrada a bcrypt: ${slug}`);
      }
    }

    if (!passwordOk) return res.status(401).json({ success: false, error: "Credenciales incorrectas." });

    const newAccessToken = crypto.randomBytes(32).toString("hex");
    await supabase.from("usuarios").update({ access_token: newAccessToken }).eq("slug", slug);

    res.json({
      success:       true,
      slug:          user.slug,
      access_token:  newAccessToken,
      business_name: user.business_name,
      email:         user.email,
      agenda_url:    `${API_URL}/agenda?u=${user.slug}`,
    });
  } catch (e) {
    console.error("Error en /login:", e.message);
    res.status(500).json({ success: false, error: e.message });
  }
});

// GET /verify-session?slug=...
// Headers: { Authorization: "Bearer <token>" }
app.get("/verify-session", async (req, res) => {
  try {
    const token = req.headers["authorization"]?.split(" ")[1];
    const slug  = getCleanSlug(req.query.slug || "");
    if (!token || !slug) return res.json({ active: false, reason: "missing_params" });

    const { data: user, error } = await supabase
      .from("usuarios").select("slug, access_token, business_name, email").eq("slug", slug).single();

    if (error || !user)                                    return res.json({ active: false, reason: "user_not_found" });
    if (!user.access_token || user.access_token !== token) return res.json({ active: false, reason: "invalid_token" });

    res.json({ active: true, slug: user.slug, business_name: user.business_name, email: user.email });
  } catch (e) {
    res.status(500).json({ active: false, error: e.message });
  }
});

// POST /api/request-password-reset — Body: { email, newPassword }
app.post("/api/request-password-reset", limiterAuth, async (req, res) => {
  try {
    const { email, newPassword } = req.body;
    if (!email || !newPassword)       return res.status(400).json({ success: false, error: "Faltan datos." });
    if (!validatePassword(newPassword)) return res.status(400).json({ success: false, error: "Mínimo 6 caracteres." });

    const { data: user } = await supabase.from("usuarios").select("slug").eq("email", email.trim().toLowerCase()).single();
    if (!user) return res.json({ success: true }); // No revelar si existe

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
// PAGOS — Mercado Pago + Mobbex
// ═══════════════════════════════════════════════════════════════════════════════

// POST /api/create-preference
// Body: { nombre, telefono, email, fecha, hora, slug, servicio_id? }
//
// LÓGICA DE COMISIÓN:
//   precioTotalServicio = precio del servicio (siempre el 100%)
//   serviceFee          = precioTotalServicio * 2.5%  ← va a nuestra cuenta
//   montoSeña           = monto_sena del usuario (33%, 50% o 100%)
//   totalCobrado        = montoSeña + serviceFee
//
app.post("/api/create-preference", limiterBooking, async (req, res) => {
  try {
    const { nombre, telefono, email, fecha, hora, slug, servicio_id } = req.body;

    if (!nombre || !telefono || !fecha || !hora || !slug) {
      return res.status(400).json({ success: false, error: "Faltan datos requeridos." });
    }
    if (email && !validateEmail(email)) return res.status(400).json({ success: false, error: "Email inválido." });

    const cleanSlug = getCleanSlug(slug);
    const { data: user, error: userError } = await supabase.from("usuarios").select("*").eq("slug", cleanSlug).single();
    if (userError || !user) return res.status(404).json({ success: false, error: "Negocio no encontrado." });

    // ── Servicio y precio base ──
    let precioTotalServicio = Number(user.precio || 0);
    let nombreServicio      = "Reserva";
    let servicioNombre      = null;

    if (servicio_id) {
      const { data: srv } = await supabase.from("servicios").select("*").eq("id", servicio_id).eq("slug", cleanSlug).single();
      if (srv) {
        precioTotalServicio = Number(srv.precio || precioTotalServicio);
        nombreServicio      = srv.nombre;
        servicioNombre      = srv.nombre;
      }
    }

    // ── Calcular montos ──
    const metodo    = user.metodo_pago || "none";
    const debePagar = metodo === "sena" || metodo === "total";
    if (!debePagar || precioTotalServicio <= 0) return res.json({ isFree: true });

    const montoServicio = metodo === "sena" && user.monto_sena
      ? Number(user.monto_sena)
      : precioTotalServicio;

    const serviceFee   = calcularServiceFee(precioTotalServicio);
    const totalCobrado = montoServicio + serviceFee;
    const conceptoPago = metodo === "sena" ? "Seña" : "Total";

    console.log(`💰 ${cleanSlug}: servicio=$${precioTotalServicio} | seña=$${montoServicio} | fee=$${serviceFee} | total=$${totalCobrado}`);

    // Metadata compartida entre pasarelas
    const metaMeta = {
      nombre,
      telefono:        cleanPhone(telefono),
      email:           email || "",
      fecha,
      hora,
      slug:            cleanSlug,
      servicio_id:     servicio_id || "",
      servicio_nombre: servicioNombre || "",
      metodo_pago:     metodo,
      precio_servicio: precioTotalServicio,
      service_fee:     serviceFee,
    };

    const successUrl = `https://negosocio.framer.website/success`;
    const cancelUrl  = `https://negosocio.framer.website/error`;

    // ── MOBBEX (prioridad — soporta split nativo) ──
    if (user.mobbex_api_key && user.mobbex_access_token) {
      try {
        const mobbexBody = {
          total:       totalCobrado,
          currency:    "ARS",
          description: `${nombreServicio} (${conceptoPago}): ${fecha} ${hora}hs`,
          reference:   `${cleanSlug}-${fecha}-${hora}`.replace(/:/g, ""),
          webhook:     `${API_URL}/webhook/mobbex`,
          return_url:  successUrl,
          items: [
            { image: "", description: `${nombreServicio} (${conceptoPago})`, quantity: 1, price: montoServicio },
            { image: "", description: "Gasto de Gestión Online", quantity: 1, price: serviceFee },
          ],
          split: [
            { tax_id: process.env.MOBBEX_PLATFORM_CUIT, total: serviceFee, fee: 0 },
          ],
          metadata: metaMeta,
          options: { button: false, redirect: true },
        };

        const mobbexRes  = await fetch("https://api.mobbex.com/p/sessions", {
          method: "POST",
          headers: { "Content-Type": "application/json", "x-api-key": user.mobbex_api_key, "x-access-token": user.mobbex_access_token },
          body: JSON.stringify(mobbexBody),
        });
        const mobbexData = await mobbexRes.json();

        if (mobbexData?.data?.url) {
          return res.json({ payment_url: mobbexData.data.url, service_fee: serviceFee, total_cobrado: totalCobrado, pasarela: "mobbex" });
        }
        console.warn("⚠️ Mobbex sin URL, fallback a MP:", mobbexData);
      } catch (e) {
        console.error("Error Mobbex, fallback MP:", e.message);
      }
    }

    // ── MERCADO PAGO (fallback — fee como ítem separado) ──
    if (user.mp_access_token) {
      try {
        const client = new MercadoPagoConfig({ accessToken: user.mp_access_token });
        const pref   = new Preference(client);

        const response = await pref.create({
          body: {
            items: [
              { title: `${nombreServicio} (${conceptoPago}): ${fecha} - ${hora}hs`, unit_price: montoServicio, quantity: 1, currency_id: "ARS" },
              { title: "Gasto de Gestión Online", unit_price: serviceFee, quantity: 1, currency_id: "ARS" },
            ],
            metadata: { ...metaMeta, tipo_pago: metodo },
            notification_url: `${API_URL}/webhook/mp`,
            back_urls: { success: successUrl, failure: cancelUrl, pending: cancelUrl },
            auto_return: "approved",
          },
        });

        return res.json({ payment_url: response.init_point, service_fee: serviceFee, total_cobrado: totalCobrado, pasarela: "mercadopago" });
      } catch (e) {
        return res.status(500).json({ success: false, error: "Error con MercadoPago." });
      }
    }

    return res.status(400).json({ success: false, error: "Sin método de pago configurado. Vinculá Mobbex o Mercado Pago desde el panel." });
  } catch (e) {
    console.error("Error en /api/create-preference:", e.message);
    res.status(500).json({ success: false, error: e.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// OAUTH — Mercado Pago
// ═══════════════════════════════════════════════════════════════════════════════

// GET /oauth-callback?code=...&state=slug
app.get("/oauth-callback", async (req, res) => {
  const { code, state: slug } = req.query;
  if (!code || !slug) return res.status(400).send("Parámetros inválidos.");

  try {
    const cleanSlug = getCleanSlug(slug);

    const response = await fetch("https://api.mercadopago.com/oauth/token", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client_id:     process.env.MP_TURNERO_CLIENT_ID,
        client_secret: process.env.MP_TURNERO_CLIENT_SECRET,
        grant_type:    "authorization_code",
        code,
        redirect_uri:  `${API_URL}/oauth-callback`,
      }),
    });

    const data = await response.json();

    if (data.access_token) {
      await supabase.from("usuarios").update({ mp_access_token: data.access_token }).eq("slug", cleanSlug);
      return res.redirect(`https://negosocio.framer.website/panel?status=mp_success&u=${cleanSlug}`);
    }

    res.redirect(`https://negosocio.framer.website/panel?status=mp_error&u=${cleanSlug}`);
  } catch (e) {
    res.status(500).send("Error al vincular Mercado Pago.");
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// WEBHOOKS
// ═══════════════════════════════════════════════════════════════════════════════

// Helper compartido: guarda turno + venta en Supabase y envía mail
async function procesarPagoConfirmado({ slug, nombre, telefono, email, fecha, hora, servicio_id, servicio_nombre, monto, moneda, service_fee, metodo_pago, payment_id, estado }) {
  let turnoId = null;

  if (estado === "aprobado") {
    const { data: turnoInsertado } = await supabase.from("turnos").insert([{
      slug,
      nombre:          nombre?.trim() || "Cliente",
      telefono:        cleanPhone(telefono?.toString() || "N/A"),
      email:           email?.trim() || null,
      fecha,
      hora,
      servicio_id:     servicio_id || null,
      servicio_nombre: servicio_nombre || null,
      estado:          "confirmado",
      metodo_pago,
      payment_id:      String(payment_id),
    }]).select().single();

    turnoId = turnoInsertado?.id || null;

    const { data: userNegocio } = await supabase.from("usuarios").select("email").eq("slug", slug).single();
    if (userNegocio?.email) {
      fetch(APPS_SCRIPT_URL, {
        method: "POST", headers: { "Content-Type": "text/plain" },
        body: JSON.stringify({
          action:        "newAppointmentEmail",
          nombreCliente: nombre?.trim() || "Cliente",
          fechaHora:     `${fecha} ${hora}`,
          adminEmail:    userNegocio.email,
          emailCliente:  email?.trim() || "",
        }),
      }).catch((e) => console.error("Error mail webhook:", e.message));
    }
  }

  await supabase.from("ventas").insert([{
    slug,
    turno_id:         turnoId,
    fecha_turno:      fecha,
    fecha_pago:       new Date().toISOString(),
    monto,
    service_fee:      service_fee || 0,
    moneda:           moneda || "ARS",
    metodo_pago,
    estado,
    nombre_cliente:   nombre?.trim() || "Cliente",
    email_cliente:    email?.trim() || null,
    telefono_cliente: cleanPhone(telefono?.toString() || ""),
    servicio_id:      servicio_id || null,
    servicio_nombre:  servicio_nombre || null,
    payment_id:       String(payment_id),
  }]);

  delete globalCache[slug];
  console.log(`✅ Webhook OK: ${slug} — ${estado} — $${monto} ARS | fee: $${service_fee}`);
}

// POST /webhook/mp — Mercado Pago notifica pagos
app.post("/webhook/mp", async (req, res) => {
  const { query, body } = req;
  try {
    if (query.topic === "payment" || body.type === "payment") {
      const paymentId = query.id || body.data?.id;
      if (!paymentId) return res.sendStatus(200);

      const payRes  = await fetch(`https://api.mercadopago.com/v1/payments/${paymentId}`, {
        headers: { Authorization: `Bearer ${process.env.MP_ACCESS_TOKEN}` },
      });
      const payData = await payRes.json();

      const slug = getCleanSlug(payData.metadata?.slug || "");
      if (!slug) return res.sendStatus(200);

      const { data: userNegocio } = await supabase.from("usuarios").select("mp_access_token").eq("slug", slug).single();
      let meta = payData.metadata;
      if (userNegocio?.mp_access_token) {
        const real = await fetch(`https://api.mercadopago.com/v1/payments/${paymentId}`, {
          headers: { Authorization: `Bearer ${userNegocio.mp_access_token}` },
        });
        meta = (await real.json()).metadata;
      }

      const estado = payData.status === "approved" ? "aprobado" : payData.status === "pending" ? "pendiente" : "rechazado";
      const monto  = Number(payData.transaction_amount || 0);

      await procesarPagoConfirmado({
        slug, nombre: meta.nombre, telefono: meta.telefono, email: meta.email,
        fecha: meta.fecha, hora: meta.hora,
        servicio_id: meta.servicio_id || null, servicio_nombre: meta.servicio_nombre || null,
        monto, moneda: payData.currency_id || "ARS",
        service_fee: Number(meta.service_fee || 0),
        metodo_pago: "mercadopago", payment_id: paymentId, estado,
      });
    }
    res.sendStatus(200);
  } catch (e) {
    console.error("Error en /webhook/mp:", e.message);
    res.sendStatus(200);
  }
});

// POST /webhook/mobbex — Mobbex notifica pagos
app.post("/webhook/mobbex", async (req, res) => {
  try {
    const body       = req.body;
    const statusCode = Number(body.status?.code || 0);
    const estado     = statusCode === 200 ? "aprobado" : statusCode >= 300 && statusCode < 400 ? "pendiente" : "rechazado";
    const meta       = body.metadata || {};
    const slug       = getCleanSlug(meta.slug || "");
    const monto      = Number(body.total || 0);
    const paymentId  = body.id || body.payment?.id || "mobbex-" + Date.now();

    if (!slug) return res.sendStatus(200);

    await procesarPagoConfirmado({
      slug, nombre: meta.nombre, telefono: meta.telefono, email: meta.email,
      fecha: meta.fecha, hora: meta.hora,
      servicio_id: meta.servicio_id || null, servicio_nombre: meta.servicio_nombre || null,
      monto, moneda: "ARS",
      service_fee: Number(meta.service_fee || 0),
      metodo_pago: "mobbex", payment_id: paymentId, estado,
    });

    res.sendStatus(200);
  } catch (e) {
    console.error("Error en /webhook/mobbex:", e.message);
    res.sendStatus(200);
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// TURNOS
// ═══════════════════════════════════════════════════════════════════════════════

// GET /get-occupied?slug=...&fecha=YYYY-MM-DD
app.get("/get-occupied", async (req, res) => {
  try {
    const slug  = getCleanSlug(req.query.slug);
    const fecha = req.query.fecha;
    if (!slug) return res.status(400).json({ success: false, error: "Slug inválido." });

    const query = supabase.from("turnos").select("hora").eq("slug", slug).neq("estado", "cancelado");
    if (fecha) query.eq("fecha", fecha);

    const { data, error } = await query;
    if (error) throw error;

    res.json({ success: true, ocupados: (data || []).map((t) => t.hora.slice(0, 5)) });
  } catch (e) {
    console.error("Error en /get-occupied:", e.message);
    res.status(500).json({ success: false, error: e.message });
  }
});

// POST /create-booking — reserva directa (sin pago)
// Body: { name, phone, email?, fecha, hora, slug, servicio_id? }
app.post("/create-booking", limiterBooking, async (req, res) => {
  try {
    const { name, phone, email, fecha, hora, slug, servicio_id } = req.body;

    if (!name || !phone || !fecha || !hora || !slug) {
      return res.status(400).json({ success: false, error: "Faltan datos requeridos." });
    }

    // FIX: limpiar espacios del teléfono antes de validar
    const phoneClean = cleanPhone(phone.toString());
    if (!validatePhone(phoneClean)) {
      return res.status(400).json({ success: false, error: "Teléfono inválido. Usá solo números (7-15 dígitos)." });
    }

    const cleanSlug = getCleanSlug(slug);
    const { data: user, error: userError } = await supabase.from("usuarios").select("*").eq("slug", cleanSlug).single();
    if (userError || !user) return res.status(404).json({ success: false, error: "Negocio no encontrado." });

    // Bloquear si el negocio requiere pago
    const requierePago = (user.mp_access_token || user.mobbex_api_key) &&
      (user.metodo_pago === "sena" || user.metodo_pago === "total");
    if (requierePago) return res.status(403).json({ success: false, error: "Este turno requiere pago previo." });

    // Anti-duplicado: un turno activo por teléfono o email
    const hoy = new Date().toISOString().split("T")[0];
    const { data: turnosExistentes } = await supabase
      .from("turnos")
      .select("id")
      .eq("slug", cleanSlug)
      .gte("fecha", hoy)
      .neq("estado", "cancelado")
      .or(`telefono.eq.${phoneClean}${email ? `,email.eq.${email.trim().toLowerCase()}` : ""}`);

    if (turnosExistentes && turnosExistentes.length > 0) {
      return res.status(400).json({ success: false, error: "Ya tenés un turno agendado activo." });
    }

    // Verificar capacidad del slot
    const capacidad = user.capacidad_por_turno || 1;
    const { count } = await supabase.from("turnos")
      .select("id", { count: "exact" })
      .eq("slug", cleanSlug).eq("fecha", fecha).eq("hora", hora).neq("estado", "cancelado");

    if (count >= capacidad) {
      return res.status(400).json({ success: false, error: "Este turno ya está lleno." });
    }

    // Nombre del servicio si corresponde
    let servicioNombre = null;
    if (servicio_id) {
      const { data: srv } = await supabase.from("servicios").select("nombre").eq("id", servicio_id).single();
      servicioNombre = srv?.nombre || null;
    }

    const { data: turno, error: turnoError } = await supabase.from("turnos").insert([{
      slug:            cleanSlug,
      nombre:          name.trim(),
      telefono:        phoneClean,
      email:           email?.trim().toLowerCase() || null,
      fecha,
      hora,
      servicio_id:     servicio_id || null,
      servicio_nombre: servicioNombre,
      estado:          "confirmado",
      metodo_pago:     "none",
    }]).select().single();

    if (turnoError) throw turnoError;

    // Notificación por email (no bloquea la respuesta)
    fetch(APPS_SCRIPT_URL, {
      method: "POST", headers: { "Content-Type": "text/plain" },
      body: JSON.stringify({
        action:        "newAppointmentEmail",
        nombreCliente: name.trim(),
        fechaHora:     `${fecha} ${hora}`,
        adminEmail:    user.email,
        emailCliente:  email?.trim() || "",
      }),
    }).catch((e) => console.error("Error mail booking:", e.message));

    delete globalCache[cleanSlug];
    res.json({ success: true, turno_id: turno.id, message: "Turno creado con éxito." });
  } catch (e) {
    console.error("Error en /create-booking:", e.message);
    res.status(500).json({ success: false, error: e.message });
  }
});

// POST /cancel-appointment (protegido) — Body: { slug, turno_id }
app.post("/cancel-appointment", requireAuth, async (req, res) => {
  try {
    const { slug, turno_id } = req.body;
    const cleanSlug = getCleanSlug(slug);
    if (!turno_id) return res.status(400).json({ success: false, error: "Falta el turno_id." });

    const { error } = await supabase.from("turnos")
      .update({ estado: "cancelado" })
      .eq("id", turno_id)
      .eq("slug", cleanSlug);

    if (error) throw error;
    delete globalCache[cleanSlug];
    res.json({ success: true, message: "Turno cancelado." });
  } catch (e) {
    console.error("Error en /cancel-appointment:", e.message);
    res.status(500).json({ success: false, error: e.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// SLOTS DISPONIBLES
// ═══════════════════════════════════════════════════════════════════════════════

// GET /slots-disponibles/:slug?fecha=YYYY-MM-DD&servicio_id=...
app.get("/slots-disponibles/:slug", async (req, res) => {
  try {
    const slug              = getCleanSlug(req.params.slug);
    const { fecha, servicio_id } = req.query;

    if (!slug || !fecha) return res.status(400).json({ success: false, error: "Faltan slug o fecha." });

    const { data: user, error: userError } = await supabase
      .from("usuarios").select("horarios, duracion_turno, capacidad_por_turno, excepciones").eq("slug", slug).single();
    if (userError || !user) return res.status(404).json({ success: false, error: "Negocio no encontrado." });

    let duracion = user.duracion_turno || 30;
    let capacidad = user.capacidad_por_turno || 1;

    if (servicio_id) {
      const { data: srv } = await supabase.from("servicios").select("duracion, capacidad").eq("id", servicio_id).eq("slug", slug).single();
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

    const { data: turnosDia } = await supabase
      .from("turnos").select("hora")
      .eq("slug", slug).eq("fecha", fecha).neq("estado", "cancelado");

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
// IMPORTANTE: /servicios/admin/:slug va ANTES de /servicios/:slug
// para que Express no interprete "admin" como un slug.
// ═══════════════════════════════════════════════════════════════════════════════

// GET /servicios/admin/:slug — todos los servicios (panel, protegido)
app.get("/servicios/admin/:slug", async (req, res) => {
  try {
    const token = req.headers["authorization"]?.split(" ")[1];
    const slug  = getCleanSlug(req.params.slug);
    if (!token || !slug) return res.status(401).json({ success: false, error: "No autorizado." });

    const { data: user } = await supabase.from("usuarios").select("access_token").eq("slug", slug).single();
    if (!user || user.access_token !== token) return res.status(401).json({ success: false, error: "No autorizado." });

    const { data, error } = await supabase.from("servicios").select("*").eq("slug", slug).order("created_at", { ascending: true });
    if (error) throw error;
    res.json({ success: true, servicios: data || [] });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// GET /servicios/:slug — servicios activos (web pública)
app.get("/servicios/:slug", async (req, res) => {
  try {
    const slug = getCleanSlug(req.params.slug);
    if (!slug) return res.status(400).json({ success: false, error: "Slug inválido." });

    const { data, error } = await supabase
      .from("servicios").select("id, nombre, descripcion, duracion, precio, capacidad")
      .eq("slug", slug).eq("activo", true).order("created_at", { ascending: true });

    if (error) throw error;
    res.json({ success: true, servicios: data || [] });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// POST /servicios/crear (protegido)
// Body: { slug, nombre, descripcion?, duracion, precio, capacidad? }
app.post("/servicios/crear", requireAuth, async (req, res) => {
  try {
    const { slug, nombre, descripcion, duracion, precio, capacidad } = req.body;
    const cleanSlug = getCleanSlug(slug);
    if (!cleanSlug || !nombre || !duracion || precio === undefined) {
      return res.status(400).json({ success: false, error: "Faltan campos." });
    }
    const { data, error } = await supabase.from("servicios").insert([{
      slug:        cleanSlug,
      nombre:      nombre.trim(),
      descripcion: descripcion?.trim() || "",
      duracion:    parseInt(duracion),
      precio:      Number(precio),
      capacidad:   parseInt(capacidad) || 1,
      activo:      true,
    }]).select().single();
    if (error) throw error;
    delete globalCache[cleanSlug];
    res.status(201).json({ success: true, servicio: data });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// POST /servicios/editar (protegido)
// Body: { slug, id, nombre?, descripcion?, duracion?, precio?, capacidad?, activo? }
app.post("/servicios/editar", requireAuth, async (req, res) => {
  try {
    const { id, slug, nombre, descripcion, duracion, precio, capacidad, activo } = req.body;
    const cleanSlug = getCleanSlug(slug);
    if (!id) return res.status(400).json({ success: false, error: "Falta el id." });

    const u = {};
    if (nombre      !== undefined) u.nombre      = nombre.trim();
    if (descripcion !== undefined) u.descripcion = descripcion.trim();
    if (duracion    !== undefined) u.duracion    = parseInt(duracion);
    if (precio      !== undefined) u.precio      = Number(precio);
    if (capacidad   !== undefined) u.capacidad   = parseInt(capacidad);
    if (activo      !== undefined) u.activo      = activo;

    const { data, error } = await supabase.from("servicios").update(u).eq("id", id).eq("slug", cleanSlug).select().single();
    if (error) throw error;
    delete globalCache[cleanSlug];
    res.json({ success: true, servicio: data });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// POST /servicios/eliminar (protegido) — Body: { slug, id }
app.post("/servicios/eliminar", requireAuth, async (req, res) => {
  try {
    const { id, slug } = req.body;
    const cleanSlug    = getCleanSlug(slug);
    if (!id) return res.status(400).json({ success: false, error: "Falta el id." });

    const { error } = await supabase.from("servicios").delete().eq("id", id).eq("slug", cleanSlug);
    if (error) throw error;
    delete globalCache[cleanSlug];
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// ADMIN STATS — Panel del profesional
// GET /admin-stats/:slug
// Modo público (?public=true): config mínima sin token — para BookingTrigger
// Modo privado (Bearer token): panel completo con turnos y métricas de ventas
// ═══════════════════════════════════════════════════════════════════════════════
app.get("/admin-stats/:slug", async (req, res) => {
  try {
    const slug     = getCleanSlug(req.params.slug);
    const isPublic = req.query.public === "true";
    const token    = req.headers["authorization"]?.split(" ")[1];

    if (!slug) return res.status(400).json({ success: false, error: "Slug inválido." });

    // ── MODO PÚBLICO ──
    if (isPublic) {
      const { data: user, error } = await supabase
        .from("usuarios")
        .select("slug, precio, monto_sena, metodo_pago, mp_access_token, mobbex_api_key")
        .eq("slug", slug)
        .single();

      if (error || !user) return res.status(404).json({ success: false, error: "Negocio no encontrado." });

      return res.json({
        stats: {
          config: {
            precio:        user.precio || 0,
            monto_sena:    user.monto_sena || 0,
            metodo_pago:   user.metodo_pago || "none",
            mp_status:     user.mp_access_token ? "Conectado" : "Desconectado",
            mobbex_status: user.mobbex_api_key  ? "Conectado" : "Desconectado",
          },
        },
      });
    }

    // ── MODO PRIVADO ──
    if (!token) return res.status(401).json({ success: false, error: "No autorizado." });

    const { data: authUser } = await supabase
      .from("usuarios").select("access_token, read_token").eq("slug", slug).single();

    // Acepta access_token (sesión activa) O read_token (solo lectura, para canvas de Framer)
    const tokenValido = authUser && (authUser.access_token === token || authUser.read_token === token);
    if (!tokenValido) {
      return res.status(401).json({ success: false, error: "No autorizado." });
    }

    const now = Date.now();
    if (globalCache[slug] && now - globalCache[slug].timestamp < CACHE_DURATION) {
      return res.json(globalCache[slug].data);
    }

    const { data: user, error: userError } = await supabase.from("usuarios").select("*").eq("slug", slug).single();
    if (userError || !user) return res.status(404).json({ success: false, error: "Usuario no encontrado." });

    const ahoraArg   = new Date(new Date().toLocaleString("en-US", { timeZone: "America/Argentina/Buenos_Aires" }));
    const anioActual = ahoraArg.getFullYear();
    const mesActual  = ahoraArg.getMonth() + 1;
    const diaHoyNum  = ahoraArg.getDate();
    const hoyISO     = `${anioActual}-${String(mesActual).padStart(2, "0")}-${String(diaHoyNum).padStart(2, "0")}`;
    const inicioMes  = `${anioActual}-${String(mesActual).padStart(2, "0")}-01`;

    const { data: turnosMes } = await supabase
      .from("turnos").select("*")
      .eq("slug", slug)
      .gte("fecha", inicioMes)
      .neq("estado", "cancelado")
      .order("fecha", { ascending: true });

    const turnosData     = turnosMes || [];
    const turnosHoy      = turnosData.filter((t) => t.fecha === hoyISO).length;
    const turnosMesTotal = turnosData.length;

    const semanas = { "Sem 1": 0, "Sem 2": 0, "Sem 3": 0, "Sem 4": 0 };
    turnosData.forEach((t) => {
      const dia = parseInt(t.fecha.split("-")[2]);
      let sem = "Sem 1";
      if (dia > 7  && dia <= 14) sem = "Sem 2";
      else if (dia > 14 && dia <= 21) sem = "Sem 3";
      else if (dia > 21) sem = "Sem 4";
      semanas[sem]++;
    });

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

    const desde90    = new Date(ahoraArg); desde90.setDate(desde90.getDate() - 90);
    const hasta7     = new Date(ahoraArg); hasta7.setDate(hasta7.getDate() + 7);
    const desde90ISO = desde90.toISOString().split("T")[0];
    const hasta7ISO  = hasta7.toISOString().split("T")[0];

    const { data: ventas } = await supabase
      .from("ventas").select("*")
      .eq("slug", slug)
      .gte("fecha_turno", desde90ISO)
      .lte("fecha_turno", hasta7ISO)
      .order("fecha_pago", { ascending: true });

    const metricas     = agruparVentas(ventas || [], hoyISO);
    const mesKey       = `${anioActual}-${String(mesActual).padStart(2, "0")}`;
    const ventasHoy    = metricas.porDia[hoyISO] || { volumen: 0, cantidad: 0, aprobado: 0, pendiente: 0, rechazado: 0 };
    const ventasMes    = metricas.porMes.find((m) => m.label === mesKey) || { volumen: 0, cantidad: 0 };
    const proximosDias = generarRangoDias(hoyISO, 7).map((fecha) => ({
      fecha,
      ...(metricas.porDia[fecha] || { volumen: 0, cantidad: 0, aprobado: 0, pendiente: 0, rechazado: 0 }),
    }));

    const feeTotal = (ventas || [])
      .filter((v) => v.estado === "aprobado")
      .reduce((acc, v) => acc + Number(v.service_fee || 0), 0);

    const finalData = {
      stats: {
        nombre_persona: user.nombre_persona,
        businessName:   user.business_name,
        slug:           user.slug,
        agenda_url:     `${API_URL}/agenda?u=${user.slug}`,

        turnosHoy,
        turnosMes:   turnosMesTotal,
        chartData:   Object.keys(semanas).map((k) => ({ label: k, turnos: semanas[k] })),
        turnosLista,

        ventas: {
          volumenTotal:   metricas.volumenTotal,
          volumenHoy:     ventasHoy.volumen,
          volumenMes:     ventasMes.volumen || 0,
          ticketPromedio: metricas.ticketPromedio,
          cantidadTotal:  metricas.cantidadTotal,
          cantidadHoy:    ventasHoy.cantidad,
          cantidadMes:    ventasMes.cantidad || 0,
          clientesNuevos: metricas.clientesNuevos,
          feeTotal,
          estados: {
            aprobado:  metricas.porEstado.aprobado  || 0,
            pendiente: metricas.porEstado.pendiente || 0,
            rechazado: metricas.porEstado.rechazado || 0,
          },
        },

        ventasPorDia: metricas.porDia,
        ventasPorSem: metricas.porSemana,
        ventasPorMes: metricas.porMes,
        proximosDias,

        horarios: user.horarios,
        config: {
          duracion:      user.duracion_turno,
          precio:        user.precio,
          monto_sena:    user.monto_sena  || 0,
          metodo_pago:   user.metodo_pago || "none",
          mp_status:     user.mp_access_token ? "Conectado" : "Desconectado",
          mobbex_status: user.mobbex_api_key  ? "Conectado" : "Desconectado",
          excepciones:   user.excepciones || [],
        },
      },
    };

    globalCache[slug] = { timestamp: now, data: finalData };
    res.json(finalData);
  } catch (e) {
    console.error("Error en /admin-stats:", e.message);
    res.status(500).json({ success: false, error: "Error al procesar estadísticas." });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// SETTINGS
// ═══════════════════════════════════════════════════════════════════════════════

// POST /update-settings (protegido)
// Body: { slug, precio?, horarios?, duracion_turno?, ocupados?, monto_sena?, metodo_pago? }
app.post("/update-settings", requireAuth, async (req, res) => {
  try {
    const { slug, precio, horarios, duracion_turno, ocupados, monto_sena, metodo_pago } = req.body;
    const cleanSlug = getCleanSlug(slug);

    const numPrecio = parseInt(precio) || 0;
    const numSena   = parseInt(monto_sena) || 0;
    if (numPrecio < 0) return res.status(400).json({ success: false, error: "El precio no puede ser negativo." });

    const u = {
      precio:         numPrecio,
      monto_sena:     numSena,
      metodo_pago:    metodo_pago || "none",
      duracion_turno: parseInt(duracion_turno) || 30,
    };
    if (horarios) u.horarios    = horarios;
    if (ocupados) u.excepciones = ocupados;

    const { error } = await supabase.from("usuarios").update(u).eq("slug", cleanSlug);
    if (error) throw error;
    delete globalCache[cleanSlug];
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
  ╔════════════════════════════════════════════╗
  ║   NegoSocio API v4.1 — Online             ║
  ║   Identificador: SLUG                     ║
  ║   Comisión plataforma: 2.5%               ║
  ║   Pasarelas: Mobbex + Mercado Pago        ║
  ║   Nuevo endpoint: GET /negocio/:slug      ║
  ║   Puerto: ${PORT}                           ║
  ╚════════════════════════════════════════════╝
  `);
});

export default app;
