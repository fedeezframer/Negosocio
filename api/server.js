import express        from "express";
import cors           from "cors";
import { createClient } from "@supabase/supabase-js";
import { MercadoPagoConfig, Preference } from "mercadopago";
import fetch          from "node-fetch";
import crypto         from "crypto";
import bcrypt         from "bcrypt";
import jwt            from "jsonwebtoken";
import rateLimit      from "express-rate-limit";

// ══════════════════════════════════════════════════════════════
// CONFIGURACIÓN GLOBAL
// ══════════════════════════════════════════════════════════════
const app = express();

const APPS_SCRIPT_URL =
  "https://script.google.com/macros/s/AKfycbzvcaYhHuyD-Xu63Aw9WpWrpcr5xmrgHW_IffXkmC90bs0pTzhWP1d8rWBaBuhG5Icx/exec";

const BCRYPT_ROUNDS  = 10;
const CACHE_DURATION = 20_000;           // ms — caché de admin-stats
const JWT_EXPIRY     = "7d";             // tokens duran 7 días
const API_URL        = process.env.API_URL || "https://negosocio.onrender.com";

// Comisión que cobramos a los negocios sobre el precio TOTAL del servicio
// Podés ajustar esto a una tarifa única ya que no hay planes
const FEE_RATE = Number(process.env.FEE_RATE || 0.025);  // 2.5% por defecto

// ══════════════════════════════════════════════════════════════
// HELPERS GENERALES
// ══════════════════════════════════════════════════════════════
const getCleanSlug = (raw) => {
  if (!raw) return "";
  return raw.toLowerCase().trim()
    .normalize("NFD").replace(/[\u0300-\u036f]/g, "")
    .replace(/\s+/g, "-").replace(/[^a-z0-9-]/g, "");
};

const validateEmail    = (e) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);
const validatePassword = (p) => p && p.length >= 6;
const validatePhone    = (p) => /^[0-9]{7,15}$/.test(p.toString().replace(/\s/g, ""));
const cleanPhone       = (p) => p.toString().replace(/\s/g, "").trim();

// ══════════════════════════════════════════════════════════════
// CACHÉ EN MEMORIA
// ══════════════════════════════════════════════════════════════
const globalCache = {};
const invalidateCache = (slug) => { delete globalCache[slug]; };

// ══════════════════════════════════════════════════════════════
// RATE LIMITING
// ══════════════════════════════════════════════════════════════
const limiterAuth    = rateLimit({ windowMs: 15 * 60 * 1000, max: 10,  message: "Demasiados intentos.", standardHeaders: true, legacyHeaders: false });
const limiterBooking = rateLimit({ windowMs: 60 * 1000,       max: 20,  message: "Demasiadas reservas." });
const limiterAPI     = rateLimit({ windowMs: 60 * 1000,       max: 200 });

// ══════════════════════════════════════════════════════════════
// CORS
// ══════════════════════════════════════════════════════════════
app.use(cors({
  origin: "*",
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization", "x-api-key"],
}));
app.use(express.json({ limit: "10mb" }));
app.use(limiterAPI);

// ══════════════════════════════════════════════════════════════
// SUPABASE
// ══════════════════════════════════════════════════════════════
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);

// ══════════════════════════════════════════════════════════════
// MIDDLEWARE: JWT AUTH
// ══════════════════════════════════════════════════════════════
// El JWT contiene: { slug, negocioId, rol: "owner" | "superadmin" }
// Se genera en /login y se verifica en cada ruta protegida.
function requireAuth(req, res, next) {
  try {
    const header = req.headers["authorization"];
    if (!header?.startsWith("Bearer ")) {
      return res.status(401).json({ success: false, error: "No autorizado: falta el token." });
    }

    const token   = header.split(" ")[1];
    const secret  = process.env.JWT_SECRET;
    if (!secret) return res.status(500).json({ success: false, error: "JWT_SECRET no configurado." });

    const payload = jwt.verify(token, secret);

    // Si es superadmin, pasa directo sin verificar el slug de la ruta
    if (payload.rol === "superadmin") {
      req.auth = payload;
      return next();
    }

    // Para owners: el slug del JWT debe coincidir con el slug de la ruta/body
    const slugRuta = getCleanSlug(
      req.params.slug || req.body?.slug || req.query?.slug || ""
    );

    if (slugRuta && payload.slug !== slugRuta) {
      return res.status(403).json({ success: false, error: "No autorizado para este negocio." });
    }

    req.auth = payload;
    next();
  } catch (e) {
    if (e.name === "TokenExpiredError") {
      return res.status(401).json({ success: false, error: "Sesión expirada. Volvé a iniciar sesión." });
    }
    res.status(401).json({ success: false, error: "Token inválido." });
  }
}

// ══════════════════════════════════════════════════════════════
// MIDDLEWARE: SUPERADMIN KEY (x-api-key header)
// ══════════════════════════════════════════════════════════════
const requireAdminKey = (req, res, next) => {
  const key = req.headers["x-api-key"];
  if (!process.env.ADMIN_SECRET || key !== process.env.ADMIN_SECRET) {
    return res.status(401).json({ success: false, error: "No autorizado." });
  }
  next();
};

// ══════════════════════════════════════════════════════════════
// HELPER: COMISIÓN
// ══════════════════════════════════════════════════════════════
function calcularServiceFee(precioTotalServicio) {
  return Math.round(Number(precioTotalServicio) * FEE_RATE);
}

// ══════════════════════════════════════════════════════════════
// HELPERS DE MÉTRICAS
// ══════════════════════════════════════════════════════════════
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
  let volumenTotal = 0, cantidadTotal = 0, feeTotal = 0;

  ventas.forEach((v) => {
    const fecha  = (v.fecha_pago || v.created_at || hoyISO).split("T")[0];
    const monto  = Number(v.monto   || 0);
    const fee    = Number(v.service_fee || 0);
    const estado = v.estado || "aprobado";
    const [va, vm, vd] = fecha.split("-").map(Number);
    const semKey = `${va}-S${Math.ceil(vd / 7)}`;
    const mesKey = `${va}-${String(vm).padStart(2, "0")}`;

    if (!porDia[fecha])    porDia[fecha]    = { volumen: 0, cantidad: 0, aprobado: 0, pendiente: 0, rechazado: 0 };
    if (!porSemana[semKey]) porSemana[semKey] = { label: semKey, volumen: 0, cantidad: 0 };
    if (!porMes[mesKey])   porMes[mesKey]   = { label: mesKey, volumen: 0, cantidad: 0 };

    porDia[fecha].volumen  += monto;
    porDia[fecha].cantidad += 1;
    porDia[fecha][estado]   = (porDia[fecha][estado] || 0) + 1;

    porSemana[semKey].volumen  += monto;
    porSemana[semKey].cantidad += 1;

    porMes[mesKey].volumen  += monto;
    porMes[mesKey].cantidad += 1;

    porEstado[estado] = (porEstado[estado] || 0) + 1;

    if (v.email_cliente)    clientesSet.add(v.email_cliente.toLowerCase());
    else if (v.telefono_cliente) clientesSet.add(v.telefono_cliente);

    if (estado === "aprobado") {
      volumenTotal  += monto;
      cantidadTotal += 1;
      feeTotal      += fee;
    }
  });

  return {
    porDia,
    porSemana:      Object.values(porSemana).sort((a, b) => a.label.localeCompare(b.label)),
    porMes:         Object.values(porMes).sort((a, b)    => a.label.localeCompare(b.label)),
    porEstado,
    volumenTotal,
    cantidadTotal,
    feeTotal,
    volumenNeto:    volumenTotal - feeTotal,
    ticketPromedio: cantidadTotal > 0 ? Math.round(volumenTotal / cantidadTotal) : 0,
    clientesNuevos: clientesSet.size,
  };
}

function calcularFrecuencia(cantidadTurnos) {
  if (cantidadTurnos >= 4) return "Concurrente";
  if (cantidadTurnos >= 2) return "Regular";
  return "Poco Frecuente";
}

// ══════════════════════════════════════════════════════════════
// RUTAS BASE
// ══════════════════════════════════════════════════════════════
app.get("/",       (_, res) => res.json({ status: "online", version: "6.0", timestamp: new Date().toISOString() }));
app.get("/health", (_, res) => res.json({ status: "ok",     timestamp: new Date().toISOString() }));


// ══════════════════════════════════════════════════════════════
// SUPERADMIN — CRUD DE NEGOCIOS
// ══════════════════════════════════════════════════════════════

/**
 * POST /admin/negocios
 * Crea un negocio nuevo. Solo accesible con x-api-key.
 * Body: { business_name, slug, email, password, nombre_persona, last_name?,
 *          precio?, duracion_turno?, telefono?, rubro? }
 */
app.post("/admin/negocios", requireAdminKey, async (req, res) => {
  try {
    const {
      business_name, slug, email, password,
      nombre_persona, last_name,
      precio, duracion_turno, telefono,
      rubro = "generico",
    } = req.body;

    if (!business_name || !slug || !email || !password) {
      return res.status(400).json({ success: false, error: "Faltan campos: business_name, slug, email, password." });
    }
    if (!validateEmail(email))       return res.status(400).json({ success: false, error: "Email inválido." });
    if (!validatePassword(password)) return res.status(400).json({ success: false, error: "Contraseña mínimo 6 caracteres." });

    const cleanSlug      = getCleanSlug(slug);
    const hashedPassword = await bcrypt.hash(String(password), BCRYPT_ROUNDS);

    const { data, error } = await supabase.from("usuarios").insert([{
      business_name:  business_name.trim(),
      slug:           cleanSlug,
      email:          email.trim().toLowerCase(),
      password:       hashedPassword,
      nombre_persona: nombre_persona?.trim() || "Dueño",
      last_name:      last_name?.trim() || "",
      precio:         parseInt(precio) || 0,
      duracion_turno: parseInt(duracion_turno) || 30,
      telefono:       telefono || null,
      metodo_pago:    "none",
      excepciones:    [],
      rubro,
      activo:         true,
    }]).select("id, slug, business_name, rubro, email").single();

    if (error) {
      if (error.code === "23505") return res.status(409).json({ success: false, error: "El slug o email ya existe." });
      throw error;
    }

    console.log(`✅ Negocio creado: ${cleanSlug} (${rubro})`);
    res.status(201).json({
      success:    true,
      negocio:    data,
      agenda_url: `${API_URL}/agenda?u=${cleanSlug}`,
    });
  } catch (e) {
    console.error("Error en POST /admin/negocios:", e.message);
    res.status(500).json({ success: false, error: e.message });
  }
});

/**
 * GET /admin/negocios
 * Lista todos los negocios (vista resumida).
 */
app.get("/admin/negocios", requireAdminKey, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("usuarios")
      .select("id, slug, business_name, rubro, nombre_persona, last_name, email, telefono, activo, metodo_pago, precio, mp_access_token, mobbex_api_key")
      .order("business_name", { ascending: true });

    if (error) throw error;

    const negocios = (data || []).map((u) => ({
      id:            u.id,
      slug:          u.slug,
      business_name: u.business_name,
      rubro:         u.rubro,
      nombre_persona: u.nombre_persona,
      last_name:     u.last_name,
      email:         u.email,
      telefono:      u.telefono,
      activo:        u.activo,
      metodo_pago:   u.metodo_pago,
      precio:        u.precio,
      tiene_mp:      !!u.mp_access_token,
      tiene_mobbex:  !!u.mobbex_api_key,
    }));

    res.json({ success: true, negocios, total: negocios.length });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

/**
 * PUT /admin/negocios/:slug
 * Edita datos de un negocio existente.
 */
app.put("/admin/negocios/:slug", requireAdminKey, async (req, res) => {
  try {
    const slug = getCleanSlug(req.params.slug);
    const allowed = ["business_name","nombre_persona","last_name","email","telefono","rubro","activo","precio","duracion_turno","notas_internas"];
    const update  = {};

    allowed.forEach((key) => {
      if (req.body[key] !== undefined) update[key] = req.body[key];
    });

    if (req.body.password) {
      update.password = await bcrypt.hash(String(req.body.password), BCRYPT_ROUNDS);
    }

    const { error } = await supabase.from("usuarios").update(update).eq("slug", slug);
    if (error) throw error;
    invalidateCache(slug);

    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

/**
 * DELETE /admin/negocios/:slug
 * Desactiva (soft delete) un negocio.
 */
app.delete("/admin/negocios/:slug", requireAdminKey, async (req, res) => {
  try {
    const slug = getCleanSlug(req.params.slug);
    const { error } = await supabase.from("usuarios").update({ activo: false }).eq("slug", slug);
    if (error) throw error;
    invalidateCache(slug);
    res.json({ success: true, message: `Negocio ${slug} desactivado.` });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});


// ══════════════════════════════════════════════════════════════
// AUTH
// ══════════════════════════════════════════════════════════════

/**
 * POST /login
 * Body: { slug, password }
 * Devuelve un JWT firmado con { slug, negocioId, rol: "owner" }
 */
app.post("/login", limiterAuth, async (req, res) => {
  try {
    const slug     = getCleanSlug(req.body.slug);
    const password = req.body.password;

    if (!slug || !password) return res.status(400).json({ success: false, error: "Faltan slug o contraseña." });

    const { data: user, error } = await supabase
      .from("usuarios")
      .select("id, slug, password, business_name, nombre_persona, last_name, email, rubro, activo")
      .eq("slug", slug)
      .single();

    if (error || !user) return res.status(401).json({ success: false, error: "Credenciales incorrectas." });
    if (!user.activo)   return res.status(403).json({ success: false, error: "Este negocio está desactivado." });

    // Soporte para contraseñas viejas sin hash (migración progresiva)
    const isHashed  = user.password?.startsWith("$2b$") || user.password?.startsWith("$2a$");
    let passwordOk  = false;
    if (isHashed) {
      passwordOk = await bcrypt.compare(String(password), user.password);
    } else {
      passwordOk = String(user.password) === String(password);
      if (passwordOk) {
        const newHash = await bcrypt.hash(String(password), BCRYPT_ROUNDS);
        await supabase.from("usuarios").update({ password: newHash }).eq("slug", slug);
        console.log(`🔐 Contraseña migrada a bcrypt: ${slug}`);
      }
    }

    if (!passwordOk) return res.status(401).json({ success: false, error: "Credenciales incorrectas." });

    const secret  = process.env.JWT_SECRET;
    if (!secret)  return res.status(500).json({ success: false, error: "JWT_SECRET no configurado." });

    const token = jwt.sign(
      { slug: user.slug, negocioId: user.id, rol: "owner" },
      secret,
      { expiresIn: JWT_EXPIRY }
    );

    res.json({
      success:        true,
      token,
      slug:           user.slug,
      business_name:  user.business_name,
      nombre_persona: user.nombre_persona,
      last_name:      user.last_name || "",
      email:          user.email,
      rubro:          user.rubro,
      agenda_url:     `${API_URL}/agenda?u=${user.slug}`,
    });
  } catch (e) {
    console.error("Error en /login:", e.message);
    res.status(500).json({ success: false, error: e.message });
  }
});

/**
 * GET /verify-session
 * Valida el JWT y devuelve datos básicos del negocio.
 */
app.get("/verify-session", requireAuth, async (req, res) => {
  try {
    const { data: user } = await supabase
      .from("usuarios")
      .select("slug, business_name, email, nombre_persona, last_name, rubro, activo")
      .eq("slug", req.auth.slug)
      .single();

    if (!user || !user.activo) return res.json({ active: false, reason: "not_found" });

    res.json({
      active: true,
      slug:           user.slug,
      business_name:  user.business_name,
      email:          user.email,
      nombre_persona: user.nombre_persona,
      last_name:      user.last_name || "",
      rubro:          user.rubro,
    });
  } catch (e) {
    res.status(500).json({ active: false, error: e.message });
  }
});

/**
 * POST /api/request-password-reset
 * Flujo de reset por email (igual que v5, via Google Apps Script)
 */
app.post("/api/request-password-reset", limiterAuth, async (req, res) => {
  try {
    const { email, newPassword } = req.body;
    if (!email || !newPassword)        return res.status(400).json({ success: false, error: "Faltan datos." });
    if (!validatePassword(newPassword)) return res.status(400).json({ success: false, error: "Mínimo 6 caracteres." });

    const { data: user } = await supabase.from("usuarios").select("slug").eq("email", email.trim().toLowerCase()).single();
    if (!user) return res.json({ success: true }); // silencioso por seguridad

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


// ══════════════════════════════════════════════════════════════
// NEGOCIO PÚBLICO (para la landing)
// ══════════════════════════════════════════════════════════════

/**
 * GET /negocio/:slug
 * Devuelve datos públicos del negocio para mostrar en la landing.
 */
app.get("/negocio/:slug", async (req, res) => {
  try {
    const slug = getCleanSlug(req.params.slug);
    if (!slug) return res.status(400).json({ success: false, error: "Slug inválido." });

    const { data: user, error } = await supabase
      .from("usuarios")
      .select("slug, business_name, rubro, horarios, excepciones, duracion_turno, capacidad_por_turno, metodo_pago, monto_sena, precio, mp_access_token, mobbex_api_key, quien_asume_comision, activo")
      .eq("slug", slug)
      .single();

    if (error || !user)  return res.status(404).json({ success: false, error: "Negocio no encontrado." });
    if (!user.activo)    return res.status(404).json({ success: false, error: "Negocio no disponible." });

    res.json({
      success: true,
      negocio: {
        slug:                user.slug,
        business_name:       user.business_name,
        rubro:               user.rubro,
        horarios:            user.horarios || {},
        excepciones:         user.excepciones || [],
        duracion_turno:      user.duracion_turno || 30,
        capacidad_por_turno: user.capacidad_por_turno || 1,
        metodo_pago:         user.metodo_pago || "none",
        monto_sena:          user.monto_sena || 0,
        precio:              user.precio || 0,
        tiene_mp:            !!user.mp_access_token,
        tiene_mobbex:        !!user.mobbex_api_key,
        quien_asume_comision: user.quien_asume_comision || "cliente",
      },
    });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});


// ══════════════════════════════════════════════════════════════
// SLOTS DISPONIBLES
// ══════════════════════════════════════════════════════════════

/**
 * GET /slots-disponibles/:slug?fecha=YYYY-MM-DD&servicio_id=...
 */
app.get("/slots-disponibles/:slug", async (req, res) => {
  try {
    const slug                   = getCleanSlug(req.params.slug);
    const { fecha, servicio_id } = req.query;

    if (!slug || !fecha) return res.status(400).json({ success: false, error: "Faltan slug o fecha." });

    const { data: user, error: userError } = await supabase
      .from("usuarios")
      .select("horarios, duracion_turno, capacidad_por_turno, excepciones, activo")
      .eq("slug", slug)
      .single();

    if (userError || !user || !user.activo) return res.status(404).json({ success: false, error: "Negocio no encontrado." });

    let duracion = user.duracion_turno || 30;
    let capacidad = user.capacidad_por_turno || 1;

    if (servicio_id) {
      const { data: srv } = await supabase.from("servicios").select("duracion, capacidad").eq("id", servicio_id).eq("slug", slug).single();
      if (srv) {
        duracion  = srv.duracion  || duracion;
        capacidad = srv.capacidad || capacidad;
      }
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
      .from("turnos")
      .select("hora, estado")
      .eq("slug", slug).eq("fecha", fecha)
      .in("estado", ["confirmado", "pendiente"]);

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
    res.status(500).json({ success: false, error: e.message });
  }
});


// ══════════════════════════════════════════════════════════════
// TURNOS — RESERVA PÚBLICA (sin login)
// ══════════════════════════════════════════════════════════════

/**
 * GET /turnos/ocupados?slug=...&fecha=...
 */
app.get("/turnos/ocupados", async (req, res) => {
  try {
    const slug  = getCleanSlug(req.query.slug);
    const fecha = req.query.fecha;
    if (!slug) return res.status(400).json({ success: false, error: "Slug inválido." });

    let q = supabase.from("turnos").select("hora").eq("slug", slug).neq("estado", "cancelado");
    if (fecha) q = q.eq("fecha", fecha);

    const { data, error } = await q;
    if (error) throw error;

    res.json({ success: true, ocupados: (data || []).map((t) => t.hora.slice(0, 5)) });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

/**
 * POST /turnos/reservar
 * El cliente reserva desde la landing (sin login).
 * Body: { slug, name, phone, email?, fecha, hora, servicio_id? }
 */
app.post("/turnos/reservar", limiterBooking, async (req, res) => {
  try {
    const { name, phone, email, fecha, hora, slug, servicio_id } = req.body;

    if (!name || !phone || !fecha || !hora || !slug) {
      return res.status(400).json({ success: false, error: "Faltan datos requeridos." });
    }

    const phoneClean = cleanPhone(phone.toString());
    if (!validatePhone(phoneClean)) {
      return res.status(400).json({ success: false, error: "Teléfono inválido (7-15 dígitos)." });
    }
    if (email && !validateEmail(email)) {
      return res.status(400).json({ success: false, error: "Email inválido." });
    }

    const cleanSlug = getCleanSlug(slug);
    const { data: user, error: userError } = await supabase.from("usuarios").select("*").eq("slug", cleanSlug).single();
    if (userError || !user)  return res.status(404).json({ success: false, error: "Negocio no encontrado." });
    if (!user.activo)        return res.status(404).json({ success: false, error: "Negocio no disponible." });

    // Si requiere pago, no se puede crear sin payment flow
    const requierePago = (user.mp_access_token || user.mobbex_api_key) && (user.metodo_pago === "sena" || user.metodo_pago === "total");
    if (requierePago) return res.status(403).json({ success: false, error: "Este turno requiere pago previo." });

    // Anti-duplicado: mismo teléfono o email con turno futuro activo
    const hoy = new Date().toISOString().split("T")[0];
    const { data: turnosExistentes } = await supabase
      .from("turnos").select("id")
      .eq("slug", cleanSlug).gte("fecha", hoy).neq("estado", "cancelado")
      .or(`telefono.eq.${phoneClean}${email ? `,email.eq.${email.trim().toLowerCase()}` : ""}`);

    if (turnosExistentes?.length > 0) {
      return res.status(400).json({ success: false, error: "Ya tenés un turno agendado activo." });
    }

    // Verificar capacidad
    const capacidad = user.capacidad_por_turno || 1;
    const { count } = await supabase.from("turnos")
      .select("id", { count: "exact" })
      .eq("slug", cleanSlug).eq("fecha", fecha).eq("hora", hora).neq("estado", "cancelado");

    if (count >= capacidad) return res.status(400).json({ success: false, error: "Este turno ya está lleno." });

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

    // Notificación al dueño
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

    invalidateCache(cleanSlug);
    res.json({ success: true, turno_id: turno.id, message: "Turno creado con éxito." });
  } catch (e) {
    console.error("Error en /turnos/reservar:", e.message);
    res.status(500).json({ success: false, error: e.message });
  }
});

/**
 * PUT /turnos/:id
 * El dueño actualiza el estado de un turno (confirmar, cancelar, completar, no_asistio).
 * También puede editar notas.
 * Requiere JWT del dueño.
 */
app.put("/turnos/:id", requireAuth, async (req, res) => {
  try {
    const { id }   = req.params;
    const { estado, notas, slug } = req.body;
    const cleanSlug = getCleanSlug(slug || req.auth.slug);

    const estadosValidos = ["confirmado", "pendiente", "cancelado", "completado", "no_asistio"];
    if (estado && !estadosValidos.includes(estado)) {
      return res.status(400).json({ success: false, error: `Estado inválido. Valores posibles: ${estadosValidos.join(", ")}` });
    }

    const update = {};
    if (estado !== undefined) update.estado = estado;
    if (notas  !== undefined) update.notas  = notas;

    const { data, error } = await supabase
      .from("turnos").update(update).eq("id", id).eq("slug", cleanSlug).select().single();

    if (error) throw error;

    invalidateCache(cleanSlug);
    res.json({ success: true, turno: data });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// Alias de compatibilidad con v5
app.post("/cancel-appointment", requireAuth, async (req, res) => {
  try {
    const { slug, turno_id } = req.body;
    const cleanSlug = getCleanSlug(slug);
    if (!turno_id) return res.status(400).json({ success: false, error: "Falta el turno_id." });

    const { error } = await supabase.from("turnos").update({ estado: "cancelado" }).eq("id", turno_id).eq("slug", cleanSlug);
    if (error) throw error;
    invalidateCache(cleanSlug);
    res.json({ success: true, message: "Turno cancelado." });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});


// ══════════════════════════════════════════════════════════════
// SERVICIOS
// ══════════════════════════════════════════════════════════════

/** GET /servicios/:slug — público, para la landing */
app.get("/servicios/:slug", async (req, res) => {
  try {
    const slug = getCleanSlug(req.params.slug);
    if (!slug) return res.status(400).json({ success: false, error: "Slug inválido." });

    const { data, error } = await supabase
      .from("servicios").select("id, nombre, descripcion, duracion, precio, capacidad")
      .eq("slug", slug).eq("activo", true)
      .order("orden", { ascending: true })
      .order("created_at", { ascending: true });

    if (error) throw error;
    res.json({ success: true, servicios: data || [] });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

/** GET /admin/servicios/:slug — lista completa (con inactivos) */
app.get("/admin/servicios/:slug", requireAuth, async (req, res) => {
  try {
    const slug = getCleanSlug(req.params.slug);
    const { data, error } = await supabase
      .from("servicios").select("*").eq("slug", slug)
      .order("orden", { ascending: true })
      .order("created_at", { ascending: true });

    if (error) throw error;
    res.json({ success: true, servicios: data || [] });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

/** POST /admin/servicios — crear */
app.post("/admin/servicios", requireAuth, async (req, res) => {
  try {
    const { slug, nombre, descripcion, duracion, precio, capacidad, orden } = req.body;
    const cleanSlug = getCleanSlug(slug || req.auth.slug);

    if (!cleanSlug || !nombre || !duracion || precio === undefined) {
      return res.status(400).json({ success: false, error: "Faltan campos: nombre, duracion, precio." });
    }

    const { data, error } = await supabase.from("servicios").insert([{
      slug:        cleanSlug,
      nombre:      nombre.trim(),
      descripcion: descripcion?.trim() || "",
      duracion:    parseInt(duracion),
      precio:      Number(precio),
      capacidad:   parseInt(capacidad) || 1,
      orden:       parseInt(orden) || 0,
      activo:      true,
    }]).select().single();

    if (error) throw error;
    invalidateCache(cleanSlug);
    res.status(201).json({ success: true, servicio: data });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

/** PUT /admin/servicios/:id — editar */
app.put("/admin/servicios/:id", requireAuth, async (req, res) => {
  try {
    const { id }     = req.params;
    const cleanSlug  = getCleanSlug(req.body.slug || req.auth.slug);
    const { nombre, descripcion, duracion, precio, capacidad, activo, orden } = req.body;

    const u = {};
    if (nombre      !== undefined) u.nombre      = nombre.trim();
    if (descripcion !== undefined) u.descripcion = descripcion.trim();
    if (duracion    !== undefined) u.duracion    = parseInt(duracion);
    if (precio      !== undefined) u.precio      = Number(precio);
    if (capacidad   !== undefined) u.capacidad   = parseInt(capacidad);
    if (activo      !== undefined) u.activo      = activo;
    if (orden       !== undefined) u.orden       = parseInt(orden);

    const { data, error } = await supabase
      .from("servicios").update(u).eq("id", id).eq("slug", cleanSlug).select().single();

    if (error) throw error;
    invalidateCache(cleanSlug);
    res.json({ success: true, servicio: data });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

/** DELETE /admin/servicios/:id — eliminar */
app.delete("/admin/servicios/:id", requireAuth, async (req, res) => {
  try {
    const { id }    = req.params;
    const cleanSlug = getCleanSlug(req.body?.slug || req.query?.slug || req.auth.slug);

    const { error } = await supabase.from("servicios").delete().eq("id", id).eq("slug", cleanSlug);
    if (error) throw error;
    invalidateCache(cleanSlug);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// Aliases de compatibilidad con v5
app.post("/servicios/crear",    requireAuth, (req, res) => { req.body.slug = req.body.slug; return app._router.handle({ ...req, url: "/admin/servicios", method: "POST" }, res, () => {}); });
// (Para compatibilidad real, mantené las rutas viejas o hacé un redirect 301)


// ══════════════════════════════════════════════════════════════
// AGENDA — Vista agrupada por fecha
// ══════════════════════════════════════════════════════════════

/**
 * GET /agenda/:slug
 * Devuelve turnos agrupados por fecha (próximos 30 días).
 */
app.get("/agenda/:slug", requireAuth, async (req, res) => {
  try {
    const slug = getCleanSlug(req.params.slug);

    const ahoraArg = new Date(new Date().toLocaleString("en-US", { timeZone: "America/Argentina/Buenos_Aires" }));
    const hoyISO   = ahoraArg.toISOString().split("T")[0];
    const hasta    = new Date(ahoraArg);
    hasta.setDate(hasta.getDate() + 30);
    const hastaISO = hasta.toISOString().split("T")[0];

    const { data: turnos, error } = await supabase
      .from("turnos").select("*")
      .eq("slug", slug)
      .gte("fecha", hoyISO)
      .lte("fecha", hastaISO)
      .neq("estado", "cancelado")
      .order("fecha", { ascending: true })
      .order("hora",  { ascending: true });

    if (error) throw error;

    const porFecha = {};
    (turnos || []).forEach((t) => {
      if (!porFecha[t.fecha]) porFecha[t.fecha] = [];
      porFecha[t.fecha].push({
        id:       t.id,
        nombre:   t.nombre,
        hora:     t.hora.slice(0, 5),
        servicio: t.servicio_nombre || null,
        estado:   t.estado,
        email:    t.email,
        telefono: t.telefono,
        notas:    t.notas || null,
      });
    });

    const dias = Object.keys(porFecha).sort().map((fecha) => ({
      fecha,
      esHoy:  fecha === hoyISO,
      turnos: porFecha[fecha],
    }));

    res.json({ success: true, hoy: hoyISO, dias });
  } catch (e) {
    console.error("Error en /agenda/:slug:", e.message);
    res.status(500).json({ success: false, error: e.message });
  }
});


// ══════════════════════════════════════════════════════════════
// COBROS — Lista de ventas
// ══════════════════════════════════════════════════════════════

/**
 * GET /cobros/:slug?limite=20&offset=0
 */
app.get("/cobros/:slug", requireAuth, async (req, res) => {
  try {
    const slug   = getCleanSlug(req.params.slug);
    const limite = parseInt(req.query.limite) || 20;
    const offset = parseInt(req.query.offset) || 0;

    const { data: ventas, error, count } = await supabase
      .from("ventas").select("*", { count: "exact" })
      .eq("slug", slug)
      .order("fecha_pago", { ascending: false })
      .range(offset, offset + limite - 1);

    if (error) throw error;

    const cobros = (ventas || []).map((v) => ({
      id:               v.id,
      monto:            v.monto,
      service_fee:      v.service_fee || 0,
      moneda:           v.moneda || "ARS",
      metodo_pago:      v.metodo_pago,
      estado:           v.estado,
      nombre_cliente:   v.nombre_cliente,
      email_cliente:    v.email_cliente,
      telefono_cliente: v.telefono_cliente,
      servicio_nombre:  v.servicio_nombre,
      fecha_turno:      v.fecha_turno,
      fecha_pago:       v.fecha_pago,
      payment_id:       v.payment_id,
    }));

    res.json({ success: true, cobros, total: count || 0, offset, limite });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});


// ══════════════════════════════════════════════════════════════
// CLIENTES — CRM básico
// ══════════════════════════════════════════════════════════════

/**
 * GET /clientes/:slug?limite=20&offset=0
 */
app.get("/clientes/:slug", requireAuth, async (req, res) => {
  try {
    const slug   = getCleanSlug(req.params.slug);
    const limite = parseInt(req.query.limite) || 20;
    const offset = parseInt(req.query.offset) || 0;

    const { data: turnos, error } = await supabase
      .from("turnos").select("nombre, email, telefono, fecha, created_at")
      .eq("slug", slug).neq("estado", "cancelado")
      .order("created_at", { ascending: false });

    if (error) throw error;

    const clientesMap = {};
    (turnos || []).forEach((t) => {
      const key = t.telefono || t.email || t.nombre;
      if (!clientesMap[key]) {
        clientesMap[key] = {
          nombre:      t.nombre,
          email:       t.email   || null,
          telefono:    t.telefono || null,
          turnos:      0,
          ultimoTurno: t.fecha,
          primerTurno: t.fecha,
        };
      }
      clientesMap[key].turnos += 1;
      if (t.fecha > clientesMap[key].ultimoTurno) clientesMap[key].ultimoTurno = t.fecha;
      if (t.fecha < clientesMap[key].primerTurno) clientesMap[key].primerTurno = t.fecha;
    });

    const clientesArr = Object.values(clientesMap)
      .map((c) => ({ ...c, frecuencia: calcularFrecuencia(c.turnos) }))
      .sort((a, b) => b.turnos - a.turnos);

    const total    = clientesArr.length;
    const clientes = clientesArr.slice(offset, offset + limite);

    res.json({
      success: true,
      clientes,
      total,
      offset,
      limite,
      stats: {
        concurrentes:   clientesArr.filter((c) => c.frecuencia === "Concurrente").length,
        regulares:      clientesArr.filter((c) => c.frecuencia === "Regular").length,
        pocoFrecuentes: clientesArr.filter((c) => c.frecuencia === "Poco Frecuente").length,
      },
    });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});


// ══════════════════════════════════════════════════════════════
// SETTINGS — Configuración del negocio
// ══════════════════════════════════════════════════════════════

/**
 * GET /settings/:slug
 * Devuelve la configuración completa del negocio.
 */
app.get("/settings/:slug", requireAuth, async (req, res) => {
  try {
    const slug = getCleanSlug(req.params.slug);
    const { data: user, error } = await supabase
      .from("usuarios")
      .select("slug, business_name, rubro, nombre_persona, last_name, email, telefono, precio, monto_sena, duracion_turno, capacidad_por_turno, metodo_pago, quien_asume_comision, horarios, excepciones, mp_access_token, mobbex_api_key, notas_internas")
      .eq("slug", slug).single();

    if (error || !user) return res.status(404).json({ success: false, error: "Negocio no encontrado." });

    res.json({
      success: true,
      settings: {
        ...user,
        mp_status:     user.mp_access_token ? "Conectado" : "Desconectado",
        mobbex_status: user.mobbex_api_key  ? "Conectado" : "Desconectado",
        // No devolver tokens reales
        mp_access_token:     undefined,
        mobbex_api_key:      undefined,
        mobbex_access_token: undefined,
      },
    });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

/**
 * POST /settings/:slug  (o PUT — ambos funcionan)
 * Actualiza configuración del negocio.
 */
const handleUpdateSettings = async (req, res) => {
  try {
    const slug = getCleanSlug(req.params.slug || req.body.slug);
    const {
      precio, horarios, duracion_turno, excepciones,
      monto_sena, metodo_pago, quien_asume_comision,
      capacidad_por_turno, business_name, telefono, rubro,
    } = req.body;

    const numPrecio = parseInt(precio);
    const numSena   = parseInt(monto_sena);
    if (!isNaN(numPrecio) && numPrecio < 0) return res.status(400).json({ success: false, error: "El precio no puede ser negativo." });

    const u = {};
    if (!isNaN(numPrecio))         u.precio              = numPrecio;
    if (!isNaN(numSena))           u.monto_sena          = numSena;
    if (metodo_pago)               u.metodo_pago         = metodo_pago;
    if (duracion_turno)            u.duracion_turno      = parseInt(duracion_turno);
    if (capacidad_por_turno)       u.capacidad_por_turno = parseInt(capacidad_por_turno);
    if (quien_asume_comision)      u.quien_asume_comision= quien_asume_comision;
    if (horarios)                  u.horarios            = horarios;
    if (excepciones)               u.excepciones         = excepciones;
    if (business_name)             u.business_name       = business_name.trim();
    if (telefono)                  u.telefono            = telefono.trim();
    if (rubro)                     u.rubro               = rubro;

    const { error } = await supabase.from("usuarios").update(u).eq("slug", slug);
    if (error) throw error;
    invalidateCache(slug);
    res.json({ success: true, message: "Configuración actualizada." });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
};

app.post("/settings/:slug",        requireAuth, handleUpdateSettings);
app.put("/settings/:slug",         requireAuth, handleUpdateSettings);
// Alias de compatibilidad v5
app.post("/update-settings",       requireAuth, handleUpdateSettings);


// ══════════════════════════════════════════════════════════════
// ADMIN STATS — Dashboard principal
// ══════════════════════════════════════════════════════════════

/**
 * GET /admin-stats/:slug
 * Stats completas para el panel del dueño.
 */
app.get("/admin-stats/:slug", requireAuth, async (req, res) => {
  try {
    const slug = getCleanSlug(req.params.slug);
    if (!slug) return res.status(400).json({ success: false, error: "Slug inválido." });

    // Caché de 20 segundos
    const now = Date.now();
    if (globalCache[slug] && now - globalCache[slug].timestamp < CACHE_DURATION) {
      return res.json(globalCache[slug].data);
    }

    const { data: user, error: userError } = await supabase.from("usuarios").select("*").eq("slug", slug).single();
    if (userError || !user) return res.status(404).json({ success: false, error: "Negocio no encontrado." });

    const ahoraArg   = new Date(new Date().toLocaleString("en-US", { timeZone: "America/Argentina/Buenos_Aires" }));
    const anioActual = ahoraArg.getFullYear();
    const mesActual  = ahoraArg.getMonth() + 1;
    const diaHoyNum  = ahoraArg.getDate();
    const hoyISO     = `${anioActual}-${String(mesActual).padStart(2, "0")}-${String(diaHoyNum).padStart(2, "0")}`;
    const inicioMes  = `${anioActual}-${String(mesActual).padStart(2, "0")}-01`;

    // Turnos del mes (no cancelados)
    const { data: turnosMes } = await supabase
      .from("turnos").select("*")
      .eq("slug", slug).gte("fecha", inicioMes).neq("estado", "cancelado")
      .order("fecha", { ascending: true }).order("hora", { ascending: true });

    const turnosData     = turnosMes || [];
    const turnosHoy      = turnosData.filter((t) => t.fecha === hoyISO).length;
    const turnosMesTotal = turnosData.length;

    // Chart semanal (distribución del mes en semanas)
    const semanas = { "Sem 1": 0, "Sem 2": 0, "Sem 3": 0, "Sem 4": 0 };
    turnosData.forEach((t) => {
      const dia = parseInt(t.fecha.split("-")[2]);
      if      (dia <= 7)  semanas["Sem 1"]++;
      else if (dia <= 14) semanas["Sem 2"]++;
      else if (dia <= 21) semanas["Sem 3"]++;
      else                semanas["Sem 4"]++;
    });

    // Lista completa de turnos del mes
    const turnosLista = turnosData.map((t) => ({
      id:       t.id,
      nombre:   t.nombre,
      telefono: t.telefono,
      email:    t.email,
      fecha:    t.fecha,
      hora:     t.hora.slice(0, 5),
      servicio: t.servicio_nombre,
      estado:   t.estado,
      notas:    t.notas || null,
      duracion: user.duracion_turno || 60,
    })).reverse();

    // Detalle de turnos de hoy (para el widget de inicio)
    const turnosHoyDetalle = turnosData
      .filter((t) => t.fecha === hoyISO)
      .sort((a, b) => a.hora.localeCompare(b.hora))
      .map((t) => ({
        id:       t.id,
        nombre:   t.nombre,
        hora:     t.hora.slice(0, 5),
        servicio: t.servicio_nombre,
        estado:   t.estado,
      }));

    // Ventas (últimos 90 días + próximos 7)
    const desde90 = new Date(ahoraArg); desde90.setDate(desde90.getDate() - 90);
    const hasta7  = new Date(ahoraArg); hasta7.setDate(hasta7.getDate() + 7);
    const { data: ventasData } = await supabase
      .from("ventas").select("*").eq("slug", slug)
      .gte("fecha_turno", desde90.toISOString().split("T")[0])
      .lte("fecha_turno", hasta7.toISOString().split("T")[0])
      .order("fecha_pago", { ascending: true });

    const metricas  = agruparVentas(ventasData || [], hoyISO);
    const mesKey    = `${anioActual}-${String(mesActual).padStart(2, "0")}`;
    const ventasHoy = metricas.porDia[hoyISO] || { volumen: 0, cantidad: 0, aprobado: 0, pendiente: 0, rechazado: 0 };
    const ventasMes = metricas.porMes.find((m) => m.label === mesKey) || { volumen: 0, cantidad: 0 };

    const proximosDias = generarRangoDias(hoyISO, 7).map((fecha) => ({
      fecha,
      ...(metricas.porDia[fecha] || { volumen: 0, cantidad: 0, aprobado: 0, pendiente: 0, rechazado: 0 }),
    }));

    // Clientes únicos totales (por teléfono)
    const { data: todosLosTurnos } = await supabase
      .from("turnos").select("telefono, email, created_at")
      .eq("slug", slug).neq("estado", "cancelado");

    const clientesUnicos    = new Set();
    const clientesMesSet    = new Set();
    const inicioMesDate     = new Date(inicioMes + "T00:00:00");

    (todosLosTurnos || []).forEach((t) => {
      const key = t.telefono || t.email?.toLowerCase();
      if (key) {
        clientesUnicos.add(key);
        if (new Date(t.created_at) >= inicioMesDate) clientesMesSet.add(key);
      }
    });

    const finalData = {
      stats: {
        nombre_persona:  user.nombre_persona,
        last_name:       user.last_name || "",
        businessName:    user.business_name,
        rubro:           user.rubro || "generico",
        slug:            user.slug,
        agenda_url:      `${API_URL}/agenda?u=${user.slug}`,

        // Turnos
        turnosHoy,
        turnosMes:       turnosMesTotal,
        turnosHoyDetalle,
        chartData:       Object.keys(semanas).map((k) => ({ label: k, turnos: semanas[k] })),
        turnosLista,

        // Clientes
        totalClientes:        clientesUnicos.size,
        clientesNuevos:       clientesMesSet.size,
        clientesConcurrentes: Math.floor(clientesUnicos.size * 0.4),

        // Ventas
        ventas: {
          volumenTotal:   metricas.volumenTotal,
          volumenNeto:    metricas.volumenNeto,
          volumenHoy:     ventasHoy.volumen,
          volumenMes:     ventasMes.volumen  || 0,
          ticketPromedio: metricas.ticketPromedio,
          cantidadTotal:  metricas.cantidadTotal,
          cantidadHoy:    ventasHoy.cantidad,
          cantidadMes:    ventasMes.cantidad || 0,
          feeTotal:       metricas.feeTotal,
          estados: {
            aprobado:  metricas.porEstado.aprobado  || 0,
            pendiente: metricas.porEstado.pendiente || 0,
            rechazado: metricas.porEstado.rechazado || 0,
          },
        },

        ventasPorDia:  metricas.porDia,
        ventasPorSem:  metricas.porSemana,
        ventasPorMes:  metricas.porMes,
        proximosDias,

        horarios: user.horarios,
        config: {
          duracion:             user.duracion_turno,
          capacidad_por_turno:  user.capacidad_por_turno || 1,
          precio:               user.precio,
          monto_sena:           user.monto_sena || 0,
          metodo_pago:          user.metodo_pago || "none",
          quien_asume_comision: user.quien_asume_comision || "cliente",
          mp_status:            user.mp_access_token ? "Conectado" : "Desconectado",
          mobbex_status:        user.mobbex_api_key  ? "Conectado" : "Desconectado",
          excepciones:          user.excepciones || [],
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


// ══════════════════════════════════════════════════════════════
// PAGOS — Mercado Pago + Mobbex
// ══════════════════════════════════════════════════════════════

/**
 * POST /api/create-preference
 * Crea una preferencia de pago (MP o Mobbex).
 */
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

    let precioTotalServicio = Number(user.precio || 0);
    let nombreServicio      = "Reserva";

    if (servicio_id) {
      const { data: srv } = await supabase.from("servicios").select("*").eq("id", servicio_id).eq("slug", cleanSlug).single();
      if (srv) {
        precioTotalServicio = Number(srv.precio || precioTotalServicio);
        nombreServicio      = srv.nombre;
      }
    }

    const metodo    = user.metodo_pago || "none";
    const debePagar = metodo === "sena" || metodo === "total";
    if (!debePagar || precioTotalServicio <= 0) return res.json({ isFree: true });

    const montoServicio = metodo === "sena" && user.monto_sena ? Number(user.monto_sena) : precioTotalServicio;
    const quienAsume    = user.quien_asume_comision || "cliente";
    const serviceFee    = calcularServiceFee(precioTotalServicio);
    const totalCobrado  = quienAsume === "cliente" ? montoServicio + serviceFee : montoServicio;
    const conceptoPago  = metodo === "sena" ? "Seña" : "Total";

    const metaMeta = {
      nombre, telefono: cleanPhone(telefono), email: email || "",
      fecha, hora, slug: cleanSlug,
      servicio_id: servicio_id || "", servicio_nombre: nombreServicio,
      metodo_pago: metodo, precio_servicio: precioTotalServicio, service_fee: serviceFee,
    };

    const successUrl = process.env.SUCCESS_URL || `${API_URL}/success`;
    const cancelUrl  = process.env.CANCEL_URL  || `${API_URL}/error`;

    // MOBBEX (prioridad)
    if (user.mobbex_api_key && user.mobbex_access_token) {
      try {
        const items = [{ image: "", description: `${nombreServicio} (${conceptoPago})`, quantity: 1, price: montoServicio }];
        if (quienAsume === "cliente") items.push({ image: "", description: "Gasto de Gestión Online", quantity: 1, price: serviceFee });

        const mobbexRes = await fetch("https://api.mobbex.com/p/sessions", {
          method: "POST",
          headers: { "Content-Type": "application/json", "x-api-key": user.mobbex_api_key, "x-access-token": user.mobbex_access_token },
          body: JSON.stringify({
            total: totalCobrado, currency: "ARS",
            description: `${nombreServicio} (${conceptoPago}): ${fecha} ${hora}hs`,
            reference: `${cleanSlug}-${fecha}-${hora}`.replace(/:/g, ""),
            webhook: `${API_URL}/webhook/mobbex`, return_url: successUrl,
            items,
            split: [{ tax_id: process.env.MOBBEX_PLATFORM_CUIT, total: serviceFee, fee: 0 }],
            metadata: metaMeta,
            options: { button: false, redirect: true },
          }),
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

    // MERCADO PAGO (fallback)
    if (user.mp_access_token) {
      try {
        const client = new MercadoPagoConfig({ accessToken: user.mp_access_token });
        const pref   = new Preference(client);

        const items = [{ title: `${nombreServicio} (${conceptoPago}): ${fecha} - ${hora}hs`, unit_price: montoServicio, quantity: 1, currency_id: "ARS" }];
        if (quienAsume === "cliente") items.push({ title: "Gasto de Gestión Online", unit_price: serviceFee, quantity: 1, currency_id: "ARS" });

        const response = await pref.create({
          body: {
            items,
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

    res.status(400).json({ success: false, error: "Sin método de pago configurado." });
  } catch (e) {
    console.error("Error en /api/create-preference:", e.message);
    res.status(500).json({ success: false, error: e.message });
  }
});


// ══════════════════════════════════════════════════════════════
// OAUTH — Mercado Pago
// ══════════════════════════════════════════════════════════════
app.get("/oauth-callback", async (req, res) => {
  const { code, state: slug } = req.query;
  if (!code || !slug) return res.status(400).send("Parámetros inválidos.");

  try {
    const cleanSlug = getCleanSlug(slug);
    const response  = await fetch("https://api.mercadopago.com/oauth/token", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client_id: process.env.MP_TURNERO_CLIENT_ID,
        client_secret: process.env.MP_TURNERO_CLIENT_SECRET,
        grant_type: "authorization_code", code,
        redirect_uri: `${API_URL}/oauth-callback`,
      }),
    });
    const data = await response.json();
    const panelUrl = process.env.PANEL_URL || "https://negosocio.framer.website/panel";

    if (data.access_token) {
      await supabase.from("usuarios").update({ mp_access_token: data.access_token }).eq("slug", cleanSlug);
      invalidateCache(cleanSlug);
      return res.redirect(`${panelUrl}?status=mp_success&u=${cleanSlug}`);
    }
    res.redirect(`${panelUrl}?status=mp_error&u=${cleanSlug}`);
  } catch (e) {
    res.status(500).send("Error al vincular Mercado Pago.");
  }
});


// ══════════════════════════════════════════════════════════════
// WEBHOOKS
// ══════════════════════════════════════════════════════════════
async function procesarPagoConfirmado({ slug, nombre, telefono, email, fecha, hora, servicio_id, servicio_nombre, monto, moneda, service_fee, metodo_pago, payment_id, estado }) {
  let turnoId = null;

  if (estado === "aprobado") {
    const { data: turnoInsertado } = await supabase.from("turnos").insert([{
      slug,
      nombre:          nombre?.trim() || "Cliente",
      telefono:        cleanPhone(telefono?.toString() || "0"),
      email:           email?.trim().toLowerCase() || null,
      fecha, hora,
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
    slug, turno_id: turnoId, fecha_turno: fecha,
    fecha_pago:       new Date().toISOString(),
    monto, service_fee: service_fee || 0,
    moneda:           moneda || "ARS",
    metodo_pago, estado,
    nombre_cliente:   nombre?.trim() || "Cliente",
    email_cliente:    email?.trim() || null,
    telefono_cliente: cleanPhone(telefono?.toString() || ""),
    servicio_id:      servicio_id || null,
    servicio_nombre:  servicio_nombre || null,
    payment_id:       String(payment_id),
  }]);

  invalidateCache(slug);
  console.log(`✅ Webhook: ${slug} — ${estado} — $${monto} ARS | fee: $${service_fee}`);
}

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
      await procesarPagoConfirmado({
        slug, nombre: meta.nombre, telefono: meta.telefono, email: meta.email,
        fecha: meta.fecha, hora: meta.hora,
        servicio_id: meta.servicio_id || null, servicio_nombre: meta.servicio_nombre || null,
        monto: Number(payData.transaction_amount || 0), moneda: payData.currency_id || "ARS",
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


// ══════════════════════════════════════════════════════════════
// 404 Y ERROR HANDLER
// ══════════════════════════════════════════════════════════════
app.use("*", (req, res) => {
  res.status(404).json({ success: false, error: "Ruta no encontrada.", path: req.originalUrl });
});

app.use((err, req, res, _next) => {
  console.error("Error no manejado:", err.message);
  res.status(500).json({ success: false, error: "Error interno del servidor." });
});


// ══════════════════════════════════════════════════════════════
// ARRANQUE
// ══════════════════════════════════════════════════════════════
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log(`
  ╔═══════════════════════════════════════════════╗
  ║   NegoSocio API v6.0 — Multi-negocio         ║
  ║   Alta manual por superadmin                 ║
  ║   JWT auth (${JWT_EXPIRY}) · Fee: ${(FEE_RATE * 100).toFixed(1)}%            ║
  ║   Endpoints: turnos, agenda, cobros, stats   ║
  ║   Puerto: ${PORT}                              ║
  ╚═══════════════════════════════════════════════╝
  `);
});

export default app;
