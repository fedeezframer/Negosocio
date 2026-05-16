import express        from "express";
import cors           from "cors";
import { createClient } from "@supabase/supabase-js";
import { MercadoPagoConfig, Preference } from "mercadopago";
import fetch          from "node-fetch";
import bcrypt         from "bcryptjs";
import jwt            from "jsonwebtoken";
import rateLimit      from "express-rate-limit";

// ══════════════════════════════════════════════════════════════
// CONFIGURACIÓN GLOBAL
// ══════════════════════════════════════════════════════════════
const app = express();

const APPS_SCRIPT_URL =
  "https://script.google.com/macros/s/AKfycbzvcaYhHuyD-Xu63Aw9WpWrpcr5xmrgHW_IffXkmC90bs0pTzhWP1d8rWBaBuhG5Icx/exec";

const BCRYPT_ROUNDS  = 10;
const CACHE_DURATION = 20_000;       // ms — caché de admin-stats
const JWT_EXPIRY     = "7d";
const API_URL        = process.env.API_URL || "https://negosocio.onrender.com";

// ══════════════════════════════════════════════════════════════
// HELPERS GENERALES
// ══════════════════════════════════════════════════════════════

// Normaliza un dominio: minúsculas, sin protocolo ni trailing slash
// "Https://MiTurno.com/" → "miturno.com"
const cleanDominio = (raw) => {
  if (!raw) return "";
  return raw.toLowerCase().trim()
    .replace(/^https?:\/\//, "")
    .replace(/\/+$/, "")
    .trim();
};

const validateEmail    = (e) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);
const validatePassword = (p) => p && p.length >= 6;
const validatePhone    = (p) => /^[0-9]{7,15}$/.test(p.toString().replace(/\s/g, ""));
const cleanPhone       = (p) => p.toString().replace(/\s/g, "").trim();

// ══════════════════════════════════════════════════════════════
// CACHÉ EN MEMORIA
// ══════════════════════════════════════════════════════════════
const globalCache = {};
const invalidateCache = (dominio) => { delete globalCache[dominio]; };

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
// JWT contiene: { dominio, negocioId, rol: "owner" | "superadmin" }
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

    // Superadmin: acceso total
    if (payload.rol === "superadmin") {
      req.auth = payload;
      return next();
    }

    // Owner: el dominio del JWT debe coincidir con el dominio de la ruta/body
    const dominioRuta = cleanDominio(
      req.params.dominio || req.body?.dominio || req.query?.dominio || ""
    );

    if (dominioRuta && payload.dominio !== dominioRuta) {
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
  let volumenTotal = 0, cantidadTotal = 0;

  ventas.forEach((v) => {
    const fecha  = (v.fecha_pago || v.created_at || hoyISO).split("T")[0];
    const monto  = Number(v.monto || 0);
    const estado = v.estado || "aprobado";
    const [va, vm, vd] = fecha.split("-").map(Number);
    const semKey = `${va}-S${Math.ceil(vd / 7)}`;
    const mesKey = `${va}-${String(vm).padStart(2, "0")}`;

    if (!porDia[fecha])     porDia[fecha]     = { volumen: 0, cantidad: 0, aprobado: 0, pendiente: 0, rechazado: 0 };
    if (!porSemana[semKey]) porSemana[semKey] = { label: semKey, volumen: 0, cantidad: 0 };
    if (!porMes[mesKey])    porMes[mesKey]    = { label: mesKey, volumen: 0, cantidad: 0 };

    porDia[fecha].volumen  += monto;
    porDia[fecha].cantidad += 1;
    porDia[fecha][estado]   = (porDia[fecha][estado] || 0) + 1;

    porSemana[semKey].volumen  += monto;
    porSemana[semKey].cantidad += 1;
    porMes[mesKey].volumen     += monto;
    porMes[mesKey].cantidad    += 1;

    porEstado[estado] = (porEstado[estado] || 0) + 1;

    if (v.email_cliente)         clientesSet.add(v.email_cliente.toLowerCase());
    else if (v.telefono_cliente) clientesSet.add(v.telefono_cliente);

    if (estado === "aprobado") {
      volumenTotal  += monto;
      cantidadTotal += 1;
    }
  });

  return {
    porDia,
    porSemana:      Object.values(porSemana).sort((a, b) => a.label.localeCompare(b.label)),
    porMes:         Object.values(porMes).sort((a, b)    => a.label.localeCompare(b.label)),
    porEstado,
    volumenTotal,
    cantidadTotal,
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
app.get("/",       (_, res) => res.json({ status: "online", version: "7.0", timestamp: new Date().toISOString() }));
app.get("/health", (_, res) => res.json({ status: "ok",     timestamp: new Date().toISOString() }));


// ══════════════════════════════════════════════════════════════
// SUPERADMIN — CRUD DE NEGOCIOS
// Protegido por x-api-key (ADMIN_SECRET en .env)
// ══════════════════════════════════════════════════════════════

/**
 * POST /superadmin/negocios
 * Registra un negocio nuevo. Solo accesible con x-api-key.
 * Body: {
 *   nombre_persona, apellido, email, telefono,   ← datos del propietario
 *   business_name, dominio,                       ← datos del negocio
 *   password, rubro?                              ← acceso y clasificación
 * }
 */
app.post("/superadmin/negocios", requireAdminKey, async (req, res) => {
  try {
    const {
      nombre_persona, apellido, email, telefono,
      business_name, dominio,
      password,
      rubro = "generico",
    } = req.body;

    // Validaciones obligatorias
    if (!nombre_persona || !email || !password || !business_name || !dominio) {
      return res.status(400).json({
        success: false,
        error: "Faltan campos obligatorios: nombre_persona, email, password, business_name, dominio.",
      });
    }
    if (!validateEmail(email))        return res.status(400).json({ success: false, error: "Email inválido." });
    if (!validatePassword(password))  return res.status(400).json({ success: false, error: "Contraseña: mínimo 6 caracteres." });
    if (telefono && !validatePhone(cleanPhone(telefono))) {
      return res.status(400).json({ success: false, error: "Teléfono inválido." });
    }

    const dominioClean   = cleanDominio(dominio);
    const hashedPassword = await bcrypt.hash(String(password), BCRYPT_ROUNDS);

    const { data, error } = await supabase.from("usuarios").insert([{
      nombre_persona:  nombre_persona.trim(),
      apellido:        apellido?.trim() || "",
      email:           email.trim().toLowerCase(),
      telefono:        telefono ? cleanPhone(telefono) : null,
      business_name:   business_name.trim(),
      dominio:         dominioClean,
      password:        hashedPassword,
      rubro,
      metodo_pago:     "none",
      porcentaje_sena: 30,
      excepciones:     [],
      activo:          true,
    }]).select("id, dominio, business_name, rubro, email, nombre_persona, apellido").single();

    if (error) {
      if (error.code === "23505") {
        return res.status(409).json({ success: false, error: "El dominio o email ya están registrados." });
      }
      throw error;
    }

    console.log(`✅ Negocio creado: ${dominioClean} (${rubro})`);
    res.status(201).json({
      success:    true,
      negocio:    data,
      panel_url:  `${process.env.PANEL_URL || "https://negosocio.framer.website/panel"}?u=${dominioClean}`,
    });
  } catch (e) {
    console.error("Error en POST /superadmin/negocios:", e.message);
    res.status(500).json({ success: false, error: e.message });
  }
});

/**
 * GET /superadmin/negocios
 * Lista todos los negocios con resumen.
 */
app.get("/superadmin/negocios", requireAdminKey, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("usuarios")
      .select("id, dominio, business_name, rubro, nombre_persona, apellido, email, telefono, activo, metodo_pago, mp_access_token, mobbex_api_key, created_at")
      .order("business_name", { ascending: true });

    if (error) throw error;

    const negocios = (data || []).map((u) => ({
      id:             u.id,
      dominio:        u.dominio,
      business_name:  u.business_name,
      rubro:          u.rubro,
      nombre_persona: u.nombre_persona,
      apellido:       u.apellido,
      email:          u.email,
      telefono:       u.telefono,
      activo:         u.activo,
      metodo_pago:    u.metodo_pago,
      tiene_mp:       !!u.mp_access_token,
      tiene_mobbex:   !!u.mobbex_api_key,
      creado:         u.created_at,
    }));

    res.json({ success: true, negocios, total: negocios.length });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

/**
 * GET /superadmin/negocios/:dominio
 * Detalle completo de un negocio (para el panel superadmin).
 */
app.get("/superadmin/negocios/:dominio", requireAdminKey, async (req, res) => {
  try {
    const dominio = cleanDominio(req.params.dominio);
    const { data: negocio, error } = await supabase
      .from("usuarios")
      .select("id, dominio, business_name, rubro, nombre_persona, apellido, email, telefono, activo, metodo_pago, porcentaje_sena, quien_asume_comision, duracion_turno, capacidad_por_turno, horarios, excepciones, notas_internas, mp_access_token, mobbex_api_key, created_at")
      .eq("dominio", dominio).single();

    if (error || !negocio) return res.status(404).json({ success: false, error: "Negocio no encontrado." });

    // Servicios del negocio
    const { data: servicios } = await supabase
      .from("servicios").select("id, nombre, descripcion, precio, duracion, capacidad, activo, orden")
      .eq("dominio", dominio).order("orden", { ascending: true });

    res.json({
      success: true,
      negocio: {
        ...negocio,
        tiene_mp:     !!negocio.mp_access_token,
        tiene_mobbex: !!negocio.mobbex_api_key,
        // No devolver tokens reales
        mp_access_token:      undefined,
        mobbex_api_key:       undefined,
        mobbex_access_token:  undefined,
      },
      servicios: servicios || [],
    });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

/**
 * PUT /superadmin/negocios/:dominio
 * Edita datos de un negocio existente.
 */
app.put("/superadmin/negocios/:dominio", requireAdminKey, async (req, res) => {
  try {
    const dominio = cleanDominio(req.params.dominio);
    const allowed = [
      "nombre_persona", "apellido", "email", "telefono",
      "business_name", "rubro", "activo", "notas_internas",
      "duracion_turno", "capacidad_por_turno",
    ];
    const update = {};

    allowed.forEach((key) => {
      if (req.body[key] !== undefined) update[key] = req.body[key];
    });

    // Si cambia el dominio (con cuidado)
    if (req.body.nuevo_dominio) {
      update.dominio = cleanDominio(req.body.nuevo_dominio);
    }

    if (req.body.password) {
      update.password = await bcrypt.hash(String(req.body.password), BCRYPT_ROUNDS);
    }

    const { error } = await supabase.from("usuarios").update(update).eq("dominio", dominio);
    if (error) throw error;
    invalidateCache(dominio);

    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

/**
 * DELETE /superadmin/negocios/:dominio
 * Desactiva (soft delete) un negocio.
 */
app.delete("/superadmin/negocios/:dominio", requireAdminKey, async (req, res) => {
  try {
    const dominio = cleanDominio(req.params.dominio);
    const { error } = await supabase.from("usuarios").update({ activo: false }).eq("dominio", dominio);
    if (error) throw error;
    invalidateCache(dominio);
    res.json({ success: true, message: `Negocio ${dominio} desactivado.` });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});


// ══════════════════════════════════════════════════════════════
// AUTH
// ══════════════════════════════════════════════════════════════

/**
 * POST /login
 * Body: { dominio, password }
 * El dueño del negocio se loguea con su dominio y contraseña.
 */
app.post("/login", limiterAuth, async (req, res) => {
  try {
    const dominio  = cleanDominio(req.body.dominio || req.body.slug); // slug como alias temporal
    const password = req.body.password;

    if (!dominio || !password) {
      return res.status(400).json({ success: false, error: "Faltan dominio y contraseña." });
    }

    const { data: user, error } = await supabase
      .from("usuarios")
      .select("id, dominio, password, business_name, nombre_persona, apellido, email, rubro, activo")
      .eq("dominio", dominio)
      .single();

    if (error || !user) return res.status(401).json({ success: false, error: "Credenciales incorrectas." });
    if (!user.activo)   return res.status(403).json({ success: false, error: "Este negocio está desactivado." });

    // Soporte para contraseñas viejas sin hash (migración progresiva)
    const isHashed = user.password?.startsWith("$2b$") || user.password?.startsWith("$2a$");
    let passwordOk = false;
    if (isHashed) {
      passwordOk = await bcrypt.compare(String(password), user.password);
    } else {
      passwordOk = String(user.password) === String(password);
      if (passwordOk) {
        const newHash = await bcrypt.hash(String(password), BCRYPT_ROUNDS);
        await supabase.from("usuarios").update({ password: newHash }).eq("dominio", dominio);
      }
    }

    if (!passwordOk) return res.status(401).json({ success: false, error: "Credenciales incorrectas." });

    const secret = process.env.JWT_SECRET;
    if (!secret)  return res.status(500).json({ success: false, error: "JWT_SECRET no configurado." });

    const token = jwt.sign(
      { dominio: user.dominio, negocioId: user.id, rol: "owner" },
      secret,
      { expiresIn: JWT_EXPIRY }
    );

    res.json({
      success:        true,
      token,
      dominio:        user.dominio,
      business_name:  user.business_name,
      nombre_persona: user.nombre_persona,
      apellido:       user.apellido || "",
      email:          user.email,
      rubro:          user.rubro,
    });
  } catch (e) {
    console.error("Error en /login:", e.message);
    res.status(500).json({ success: false, error: e.message });
  }
});

/**
 * GET /verify-session
 */
app.get("/verify-session", requireAuth, async (req, res) => {
  try {
    const { data: user } = await supabase
      .from("usuarios")
      .select("dominio, business_name, email, nombre_persona, apellido, rubro, activo")
      .eq("dominio", req.auth.dominio)
      .single();

    if (!user || !user.activo) return res.json({ active: false, reason: "not_found" });

    res.json({
      active:         true,
      dominio:        user.dominio,
      business_name:  user.business_name,
      email:          user.email,
      nombre_persona: user.nombre_persona,
      apellido:       user.apellido || "",
      rubro:          user.rubro,
    });
  } catch (e) {
    res.status(500).json({ active: false, error: e.message });
  }
});

/**
 * POST /api/request-password-reset
 */
app.post("/api/request-password-reset", limiterAuth, async (req, res) => {
  try {
    const { email, newPassword } = req.body;
    if (!email || !newPassword)         return res.status(400).json({ success: false, error: "Faltan datos." });
    if (!validatePassword(newPassword)) return res.status(400).json({ success: false, error: "Mínimo 6 caracteres." });

    const { data: user } = await supabase.from("usuarios").select("dominio").eq("email", email.trim().toLowerCase()).single();
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
// NEGOCIO PÚBLICO (para la landing del cliente)
// ══════════════════════════════════════════════════════════════

/**
 * GET /negocio/:dominio
 * Devuelve datos públicos del negocio para la landing.
 * El frontend puede llamar con el dominio de la URL (window.location.hostname).
 */
app.get("/negocio/:dominio", async (req, res) => {
  try {
    const dominio = cleanDominio(req.params.dominio);
    if (!dominio) return res.status(400).json({ success: false, error: "Dominio inválido." });

    const { data: user, error } = await supabase
      .from("usuarios")
      .select("dominio, business_name, rubro, horarios, excepciones, duracion_turno, capacidad_por_turno, metodo_pago, porcentaje_sena, mp_access_token, mobbex_api_key, quien_asume_comision, activo")
      .eq("dominio", dominio)
      .single();

    if (error || !user)  return res.status(404).json({ success: false, error: "Negocio no encontrado." });
    if (!user.activo)    return res.status(404).json({ success: false, error: "Negocio no disponible." });

    res.json({
      success: true,
      negocio: {
        dominio:              user.dominio,
        business_name:        user.business_name,
        rubro:                user.rubro,
        horarios:             user.horarios || {},
        excepciones:          user.excepciones || [],
        duracion_turno:       user.duracion_turno || 30,
        capacidad_por_turno:  user.capacidad_por_turno || 1,
        metodo_pago:          user.metodo_pago || "none",
        porcentaje_sena:      user.porcentaje_sena || 30,
        tiene_mp:             !!user.mp_access_token,
        tiene_mobbex:         !!user.mobbex_api_key,
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
 * GET /slots-disponibles/:dominio?fecha=YYYY-MM-DD&servicio_id=...
 * Si se pasa servicio_id, usa la duración y capacidad de ese servicio.
 */
app.get("/slots-disponibles/:dominio", async (req, res) => {
  try {
    const dominio                = cleanDominio(req.params.dominio);
    const { fecha, servicio_id } = req.query;

    if (!dominio || !fecha) return res.status(400).json({ success: false, error: "Faltan dominio o fecha." });

    const { data: user, error: userError } = await supabase
      .from("usuarios")
      .select("horarios, duracion_turno, capacidad_por_turno, excepciones, activo")
      .eq("dominio", dominio)
      .single();

    if (userError || !user || !user.activo) {
      return res.status(404).json({ success: false, error: "Negocio no encontrado." });
    }

    // Por defecto toma la configuración global del negocio
    let duracion  = user.duracion_turno       || 30;
    let capacidad = user.capacidad_por_turno  || 1;

    // Si se especificó un servicio, usar SU duración y capacidad
    if (servicio_id) {
      const { data: srv } = await supabase
        .from("servicios")
        .select("duracion, capacidad")
        .eq("id", servicio_id)
        .eq("dominio", dominio)
        .single();
      if (srv) {
        duracion  = srv.duracion  || duracion;
        capacidad = srv.capacidad || capacidad;
      }
    }

    // Excepciones: día completamente bloqueado
    const excepcionesArr = user.excepciones || [];
    const estaExceptuado = Array.isArray(excepcionesArr)
      ? excepcionesArr.some((e) =>
          typeof e === "string" ? e === fecha : e?.fecha === fecha && e?.type === "block"
        )
      : false;
    if (estaExceptuado) return res.json({ success: true, slots: [] });

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
      .eq("dominio", dominio).eq("fecha", fecha)
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
 * GET /turnos/ocupados?dominio=...&fecha=...
 */
app.get("/turnos/ocupados", async (req, res) => {
  try {
    const dominio = cleanDominio(req.query.dominio || req.query.slug);
    const fecha   = req.query.fecha;
    if (!dominio) return res.status(400).json({ success: false, error: "Dominio inválido." });

    let q = supabase.from("turnos").select("hora").eq("dominio", dominio).neq("estado", "cancelado");
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
 * Body: { dominio, name, phone, email?, fecha, hora, servicio_id? }
 */
app.post("/turnos/reservar", limiterBooking, async (req, res) => {
  try {
    const { name, phone, email, fecha, hora, dominio, servicio_id } = req.body;

    if (!name || !phone || !fecha || !hora || !dominio) {
      return res.status(400).json({ success: false, error: "Faltan datos requeridos." });
    }

    const phoneClean = cleanPhone(phone.toString());
    if (!validatePhone(phoneClean)) {
      return res.status(400).json({ success: false, error: "Teléfono inválido (7-15 dígitos)." });
    }
    if (email && !validateEmail(email)) {
      return res.status(400).json({ success: false, error: "Email inválido." });
    }

    const dominioClean = cleanDominio(dominio);
    const { data: user, error: userError } = await supabase
      .from("usuarios").select("*").eq("dominio", dominioClean).single();
    if (userError || !user)  return res.status(404).json({ success: false, error: "Negocio no encontrado." });
    if (!user.activo)        return res.status(404).json({ success: false, error: "Negocio no disponible." });

    // Si requiere pago previo, rechazar reserva directa
    const requierePago = (user.mp_access_token || user.mobbex_api_key)
      && (user.metodo_pago === "sena" || user.metodo_pago === "total");
    if (requierePago) {
      return res.status(403).json({ success: false, error: "Este turno requiere pago previo." });
    }

    // Anti-duplicado
    const hoy = new Date().toISOString().split("T")[0];
    const { data: turnosExistentes } = await supabase
      .from("turnos").select("id")
      .eq("dominio", dominioClean).gte("fecha", hoy).neq("estado", "cancelado")
      .or(`telefono.eq.${phoneClean}${email ? `,email.eq.${email.trim().toLowerCase()}` : ""}`);

    if (turnosExistentes?.length > 0) {
      return res.status(400).json({ success: false, error: "Ya tenés un turno agendado activo." });
    }

    // Capacidad
    let capacidad = user.capacidad_por_turno || 1;
    let servicioNombre = null;
    let precioCobrado  = 0;

    if (servicio_id) {
      const { data: srv } = await supabase
        .from("servicios").select("nombre, capacidad, precio")
        .eq("id", servicio_id).single();
      if (srv) {
        servicioNombre = srv.nombre;
        capacidad      = srv.capacidad || capacidad;
        precioCobrado  = Number(srv.precio || 0);
      }
    }

    const { count } = await supabase.from("turnos")
      .select("id", { count: "exact" })
      .eq("dominio", dominioClean).eq("fecha", fecha).eq("hora", hora).neq("estado", "cancelado");

    if (count >= capacidad) {
      return res.status(400).json({ success: false, error: "Este turno ya está lleno." });
    }

    const { data: turno, error: turnoError } = await supabase.from("turnos").insert([{
      dominio:         dominioClean,
      nombre:          name.trim(),
      telefono:        phoneClean,
      email:           email?.trim().toLowerCase() || null,
      fecha,
      hora,
      servicio_id:     servicio_id || null,
      servicio_nombre: servicioNombre,
      precio_cobrado:  precioCobrado,
      estado:          "confirmado",
      metodo_pago:     "none",
    }]).select().single();

    if (turnoError) throw turnoError;

    // Notificación email al dueño
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

    invalidateCache(dominioClean);
    res.json({ success: true, turno_id: turno.id, message: "Turno creado con éxito." });
  } catch (e) {
    console.error("Error en /turnos/reservar:", e.message);
    res.status(500).json({ success: false, error: e.message });
  }
});

/**
 * PUT /turnos/:id
 * El dueño actualiza estado o notas de un turno.
 */
app.put("/turnos/:id", requireAuth, async (req, res) => {
  try {
    const { id }     = req.params;
    const { estado, notas, dominio } = req.body;
    const dominioClean = cleanDominio(dominio || req.auth.dominio);

    const estadosValidos = ["confirmado", "pendiente", "cancelado", "completado", "no_asistio"];
    if (estado && !estadosValidos.includes(estado)) {
      return res.status(400).json({ success: false, error: `Estado inválido. Valores posibles: ${estadosValidos.join(", ")}` });
    }

    const update = {};
    if (estado !== undefined) update.estado = estado;
    if (notas  !== undefined) update.notas  = notas;

    const { data, error } = await supabase
      .from("turnos").update(update).eq("id", id).eq("dominio", dominioClean).select().single();

    if (error) throw error;
    invalidateCache(dominioClean);
    res.json({ success: true, turno: data });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});


// ══════════════════════════════════════════════════════════════
// SERVICIOS
// ══════════════════════════════════════════════════════════════

/** GET /servicios/:dominio — público, para la landing */
app.get("/servicios/:dominio", async (req, res) => {
  try {
    const dominio = cleanDominio(req.params.dominio);
    if (!dominio) return res.status(400).json({ success: false, error: "Dominio inválido." });

    const { data, error } = await supabase
      .from("servicios")
      .select("id, nombre, descripcion, duracion, precio, capacidad")
      .eq("dominio", dominio).eq("activo", true)
      .order("orden", { ascending: true })
      .order("created_at", { ascending: true });

    if (error) throw error;
    res.json({ success: true, servicios: data || [] });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

/** GET /admin/servicios/:dominio — lista completa (con inactivos) */
app.get("/admin/servicios/:dominio", requireAuth, async (req, res) => {
  try {
    const dominio = cleanDominio(req.params.dominio);
    const { data, error } = await supabase
      .from("servicios").select("*").eq("dominio", dominio)
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
    const { dominio, nombre, descripcion, duracion, precio, capacidad, orden } = req.body;
    const dominioClean = cleanDominio(dominio || req.auth.dominio);

    if (!dominioClean || !nombre || !duracion || precio === undefined) {
      return res.status(400).json({ success: false, error: "Faltan campos: nombre, duracion, precio." });
    }

    const { data, error } = await supabase.from("servicios").insert([{
      dominio:     dominioClean,
      nombre:      nombre.trim(),
      descripcion: descripcion?.trim() || "",
      duracion:    parseInt(duracion),
      precio:      Number(precio),
      capacidad:   parseInt(capacidad) || 1,
      orden:       parseInt(orden) || 0,
      activo:      true,
    }]).select().single();

    if (error) throw error;
    invalidateCache(dominioClean);
    res.status(201).json({ success: true, servicio: data });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

/** PUT /admin/servicios/:id — editar */
app.put("/admin/servicios/:id", requireAuth, async (req, res) => {
  try {
    const { id }        = req.params;
    const dominioClean  = cleanDominio(req.body.dominio || req.auth.dominio);
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
      .from("servicios").update(u).eq("id", id).eq("dominio", dominioClean).select().single();

    if (error) throw error;
    invalidateCache(dominioClean);
    res.json({ success: true, servicio: data });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

/** DELETE /admin/servicios/:id — eliminar */
app.delete("/admin/servicios/:id", requireAuth, async (req, res) => {
  try {
    const { id }       = req.params;
    const dominioClean = cleanDominio(req.body?.dominio || req.query?.dominio || req.auth.dominio);

    const { error } = await supabase.from("servicios").delete().eq("id", id).eq("dominio", dominioClean);
    if (error) throw error;
    invalidateCache(dominioClean);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});


// ══════════════════════════════════════════════════════════════
// AGENDA — Vista agrupada por fecha (próximos 30 días)
// ══════════════════════════════════════════════════════════════

app.get("/agenda/:dominio", requireAuth, async (req, res) => {
  try {
    const dominio = cleanDominio(req.params.dominio);

    const ahoraArg = new Date(new Date().toLocaleString("en-US", { timeZone: "America/Argentina/Buenos_Aires" }));
    const hoyISO   = ahoraArg.toISOString().split("T")[0];
    const hasta    = new Date(ahoraArg);
    hasta.setDate(hasta.getDate() + 30);
    const hastaISO = hasta.toISOString().split("T")[0];

    const { data: turnos, error } = await supabase
      .from("turnos").select("*")
      .eq("dominio", dominio)
      .gte("fecha", hoyISO).lte("fecha", hastaISO)
      .neq("estado", "cancelado")
      .order("fecha", { ascending: true })
      .order("hora",  { ascending: true });

    if (error) throw error;

    const porFecha = {};
    (turnos || []).forEach((t) => {
      if (!porFecha[t.fecha]) porFecha[t.fecha] = [];
      porFecha[t.fecha].push({
        id:             t.id,
        nombre:         t.nombre,
        hora:           t.hora.slice(0, 5),
        servicio:       t.servicio_nombre || null,
        precio_cobrado: t.precio_cobrado  || 0,
        estado:         t.estado,
        email:          t.email,
        telefono:       t.telefono,
        notas:          t.notas || null,
      });
    });

    const dias = Object.keys(porFecha).sort().map((fecha) => ({
      fecha,
      esHoy:  fecha === hoyISO,
      turnos: porFecha[fecha],
    }));

    res.json({ success: true, hoy: hoyISO, dias });
  } catch (e) {
    console.error("Error en /agenda/:dominio:", e.message);
    res.status(500).json({ success: false, error: e.message });
  }
});


// ══════════════════════════════════════════════════════════════
// COBROS — Lista de ventas del negocio
// ══════════════════════════════════════════════════════════════

app.get("/cobros/:dominio", requireAuth, async (req, res) => {
  try {
    const dominio = cleanDominio(req.params.dominio);
    const limite  = parseInt(req.query.limite) || 20;
    const offset  = parseInt(req.query.offset) || 0;

    const { data: ventas, error, count } = await supabase
      .from("ventas").select("*", { count: "exact" })
      .eq("dominio", dominio)
      .order("fecha_pago", { ascending: false })
      .range(offset, offset + limite - 1);

    if (error) throw error;

    const cobros = (ventas || []).map((v) => ({
      id:               v.id,
      monto:            v.monto,
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

app.get("/clientes/:dominio", requireAuth, async (req, res) => {
  try {
    const dominio = cleanDominio(req.params.dominio);
    const limite  = parseInt(req.query.limite) || 20;
    const offset  = parseInt(req.query.offset) || 0;

    const { data: turnos, error } = await supabase
      .from("turnos").select("nombre, email, telefono, fecha, created_at")
      .eq("dominio", dominio).neq("estado", "cancelado")
      .order("created_at", { ascending: false });

    if (error) throw error;

    const clientesMap = {};
    (turnos || []).forEach((t) => {
      const key = t.telefono || t.email || t.nombre;
      if (!clientesMap[key]) {
        clientesMap[key] = {
          nombre:      t.nombre,
          email:       t.email    || null,
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

    res.json({
      success: true,
      clientes: clientesArr.slice(offset, offset + limite),
      total:    clientesArr.length,
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
// SETTINGS — Configuración del negocio (panel del dueño)
// ══════════════════════════════════════════════════════════════

app.get("/settings/:dominio", requireAuth, async (req, res) => {
  try {
    const dominio = cleanDominio(req.params.dominio);
    const { data: user, error } = await supabase
      .from("usuarios")
      .select("dominio, business_name, rubro, nombre_persona, apellido, email, telefono, duracion_turno, capacidad_por_turno, metodo_pago, porcentaje_sena, quien_asume_comision, horarios, excepciones, mp_access_token, mobbex_api_key, notas_internas")
      .eq("dominio", dominio).single();

    if (error || !user) return res.status(404).json({ success: false, error: "Negocio no encontrado." });

    res.json({
      success: true,
      settings: {
        ...user,
        mp_status:           user.mp_access_token ? "Conectado" : "Desconectado",
        mobbex_status:       user.mobbex_api_key  ? "Conectado" : "Desconectado",
        mp_access_token:     undefined,
        mobbex_api_key:      undefined,
        mobbex_access_token: undefined,
      },
    });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

const handleUpdateSettings = async (req, res) => {
  try {
    const dominio = cleanDominio(req.params.dominio || req.body.dominio);
    const {
      horarios, duracion_turno, excepciones,
      porcentaje_sena, metodo_pago, quien_asume_comision,
      capacidad_por_turno, business_name, telefono, rubro,
    } = req.body;

    const u = {};
    if (metodo_pago)               u.metodo_pago         = metodo_pago;
    if (porcentaje_sena !== undefined && !isNaN(parseInt(porcentaje_sena))) {
      u.porcentaje_sena = Math.min(100, Math.max(1, parseInt(porcentaje_sena)));
    }
    if (duracion_turno)            u.duracion_turno      = parseInt(duracion_turno);
    if (capacidad_por_turno)       u.capacidad_por_turno = parseInt(capacidad_por_turno);
    if (quien_asume_comision)      u.quien_asume_comision= quien_asume_comision;
    if (horarios)                  u.horarios            = horarios;
    if (excepciones !== undefined) u.excepciones         = excepciones;
    if (business_name)             u.business_name       = business_name.trim();
    if (telefono)                  u.telefono            = telefono.trim();
    if (rubro)                     u.rubro               = rubro;

    const { error } = await supabase.from("usuarios").update(u).eq("dominio", dominio);
    if (error) throw error;
    invalidateCache(dominio);
    res.json({ success: true, message: "Configuración actualizada." });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
};

app.post("/settings/:dominio", requireAuth, handleUpdateSettings);
app.put("/settings/:dominio",  requireAuth, handleUpdateSettings);


// ══════════════════════════════════════════════════════════════
// ADMIN STATS — Dashboard principal del dueño
// ══════════════════════════════════════════════════════════════

app.get("/admin-stats/:dominio", requireAuth, async (req, res) => {
  try {
    const dominio = cleanDominio(req.params.dominio);
    if (!dominio) return res.status(400).json({ success: false, error: "Dominio inválido." });

    // Caché de 20 segundos
    const now = Date.now();
    if (globalCache[dominio] && now - globalCache[dominio].timestamp < CACHE_DURATION) {
      return res.json(globalCache[dominio].data);
    }

    const { data: user, error: userError } = await supabase
      .from("usuarios").select("*").eq("dominio", dominio).single();
    if (userError || !user) return res.status(404).json({ success: false, error: "Negocio no encontrado." });

    const ahoraArg   = new Date(new Date().toLocaleString("en-US", { timeZone: "America/Argentina/Buenos_Aires" }));
    const anioActual = ahoraArg.getFullYear();
    const mesActual  = ahoraArg.getMonth() + 1;
    const diaHoyNum  = ahoraArg.getDate();
    const hoyISO     = `${anioActual}-${String(mesActual).padStart(2, "0")}-${String(diaHoyNum).padStart(2, "0")}`;
    const inicioMes  = `${anioActual}-${String(mesActual).padStart(2, "0")}-01`;

    // Turnos del mes
    const { data: turnosMes } = await supabase
      .from("turnos").select("*")
      .eq("dominio", dominio).gte("fecha", inicioMes).neq("estado", "cancelado")
      .order("fecha", { ascending: true }).order("hora", { ascending: true });

    const turnosData     = turnosMes || [];
    const turnosHoy      = turnosData.filter((t) => t.fecha === hoyISO).length;
    const turnosMesTotal = turnosData.length;

    // Chart semanal
    const semanas = { "Sem 1": 0, "Sem 2": 0, "Sem 3": 0, "Sem 4": 0 };
    turnosData.forEach((t) => {
      const dia = parseInt(t.fecha.split("-")[2]);
      if      (dia <= 7)  semanas["Sem 1"]++;
      else if (dia <= 14) semanas["Sem 2"]++;
      else if (dia <= 21) semanas["Sem 3"]++;
      else                semanas["Sem 4"]++;
    });

    const turnosLista = turnosData.map((t) => ({
      id:             t.id,
      nombre:         t.nombre,
      telefono:       t.telefono,
      email:          t.email,
      fecha:          t.fecha,
      hora:           t.hora.slice(0, 5),
      servicio:       t.servicio_nombre,
      precio_cobrado: t.precio_cobrado || 0,
      estado:         t.estado,
      notas:          t.notas || null,
      duracion:       user.duracion_turno || 30,
    })).reverse();

    const turnosHoyDetalle = turnosData
      .filter((t) => t.fecha === hoyISO)
      .sort((a, b) => a.hora.localeCompare(b.hora))
      .map((t) => ({
        id:      t.id,
        nombre:  t.nombre,
        hora:    t.hora.slice(0, 5),
        servicio: t.servicio_nombre,
        estado:  t.estado,
      }));

    // Ventas (últimos 90 días)
    const desde90 = new Date(ahoraArg); desde90.setDate(desde90.getDate() - 90);
    const hasta7  = new Date(ahoraArg); hasta7.setDate(hasta7.getDate() + 7);
    const { data: ventasData } = await supabase
      .from("ventas").select("*").eq("dominio", dominio)
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

    // Clientes únicos totales
    const { data: todosLosTurnos } = await supabase
      .from("turnos").select("telefono, email, created_at")
      .eq("dominio", dominio).neq("estado", "cancelado");

    const clientesUnicos = new Set();
    const clientesMesSet = new Set();
    const inicioMesDate  = new Date(inicioMes + "T00:00:00");

    (todosLosTurnos || []).forEach((t) => {
      const key = t.telefono || t.email?.toLowerCase();
      if (key) {
        clientesUnicos.add(key);
        if (new Date(t.created_at) >= inicioMesDate) clientesMesSet.add(key);
      }
    });

    // Ventajas por día del mes hasta hoy
    const ventasPorDia = {};
    generarRangoDias(inicioMes, diaHoyNum).forEach((d) => {
      ventasPorDia[d] = metricas.porDia[d] || { volumen: 0, cantidad: 0, aprobado: 0, pendiente: 0, rechazado: 0 };
    });

    const finalData = {
      turnosHoy,
      turnosMes:       turnosMesTotal,
      turnosHoyDetalle,
      chartData:       Object.keys(semanas).map((k) => ({ label: k, turnos: semanas[k] })),
      turnosLista,

      totalClientes:        clientesUnicos.size,
      clientesNuevos:       clientesMesSet.size,
      clientesConcurrentes: Math.floor(clientesUnicos.size * 0.4),

      ventas: {
        volumenTotal:   metricas.volumenTotal,
        volumenHoy:     ventasHoy.volumen,
        volumenMes:     ventasMes.volumen  || 0,
        ticketPromedio: metricas.ticketPromedio,
        cantidadTotal:  metricas.cantidadTotal,
        cantidadHoy:    ventasHoy.cantidad,
        cantidadMes:    ventasMes.cantidad || 0,
        estados: {
          aprobado:  metricas.porEstado.aprobado  || 0,
          pendiente: metricas.porEstado.pendiente || 0,
          rechazado: metricas.porEstado.rechazado || 0,
        },
      },

      ventasPorDia,
      ventasPorSem:  metricas.porSemana,
      ventasPorMes:  metricas.porMes,
      proximosDias,

      horarios:      user.horarios,
      config: {
        duracion:             user.duracion_turno      || 30,
        capacidad_por_turno:  user.capacidad_por_turno || 1,
        metodo_pago:          user.metodo_pago         || "none",
        porcentaje_sena:      user.porcentaje_sena     || 30,
        quien_asume_comision: user.quien_asume_comision|| "cliente",
        mp_status:            user.mp_access_token ? "Conectado" : "Desconectado",
        mobbex_status:        user.mobbex_api_key  ? "Conectado" : "Desconectado",
        excepciones:          user.excepciones     || [],
      },

      businessName:   user.business_name,
      nombre_persona: user.nombre_persona,
      apellido:       user.apellido || "",
      dominio:        user.dominio,
      rubro:          user.rubro || "generico",
    };

    globalCache[dominio] = { timestamp: now, data: finalData };
    res.json(finalData);
  } catch (e) {
    console.error("Error en /admin-stats:", e.message);
    res.status(500).json({ success: false, error: "Error al procesar estadísticas." });
  }
});


// ══════════════════════════════════════════════════════════════
// PAGOS — Mercado Pago + Mobbex
// El precio siempre viene del servicio seleccionado.
// No hay comisión de plataforma (service_fee = 0 siempre).
// ══════════════════════════════════════════════════════════════

app.post("/api/create-preference", limiterBooking, async (req, res) => {
  try {
    const { nombre, telefono, email, fecha, hora, dominio, servicio_id } = req.body;

    if (!nombre || !telefono || !fecha || !hora || !dominio) {
      return res.status(400).json({ success: false, error: "Faltan datos requeridos." });
    }
    if (email && !validateEmail(email)) {
      return res.status(400).json({ success: false, error: "Email inválido." });
    }

    const dominioClean = cleanDominio(dominio);
    const { data: user, error: userError } = await supabase
      .from("usuarios").select("*").eq("dominio", dominioClean).single();
    if (userError || !user) return res.status(404).json({ success: false, error: "Negocio no encontrado." });

    // Precio: obligatoriamente del servicio
    let precioServicio = 0;
    let nombreServicio = "Reserva";

    if (servicio_id) {
      const { data: srv } = await supabase
        .from("servicios").select("nombre, precio")
        .eq("id", servicio_id).eq("dominio", dominioClean).single();
      if (srv) {
        precioServicio = Number(srv.precio || 0);
        nombreServicio = srv.nombre;
      }
    }

    const metodo    = user.metodo_pago || "none";
    const debePagar = metodo === "sena" || metodo === "total";
    if (!debePagar || precioServicio <= 0) return res.json({ isFree: true });

    // Seña: porcentaje del precio del servicio
    const montoACobrar = metodo === "sena"
      ? Math.round(precioServicio * (user.porcentaje_sena || 30) / 100)
      : precioServicio;

    const conceptoPago = metodo === "sena"
      ? `Seña ${user.porcentaje_sena || 30}%`
      : "Total";

    const metaMeta = {
      nombre,
      telefono:        cleanPhone(telefono),
      email:           email || "",
      fecha,
      hora,
      dominio:         dominioClean,
      servicio_id:     servicio_id || "",
      servicio_nombre: nombreServicio,
      metodo_pago:     metodo,
      precio_servicio: precioServicio,
    };

    const successUrl = process.env.SUCCESS_URL || `${API_URL}/success`;
    const cancelUrl  = process.env.CANCEL_URL  || `${API_URL}/error`;

    // MOBBEX (prioridad)
    if (user.mobbex_api_key && user.mobbex_access_token) {
      try {
        const mobbexRes = await fetch("https://api.mobbex.com/p/sessions", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "x-api-key":      user.mobbex_api_key,
            "x-access-token": user.mobbex_access_token,
          },
          body: JSON.stringify({
            total:       montoACobrar,
            currency:    "ARS",
            description: `${nombreServicio} (${conceptoPago}): ${fecha} ${hora}hs`,
            reference:   `${dominioClean}-${fecha}-${hora}`.replace(/[:.]/g, ""),
            webhook:     `${API_URL}/webhook/mobbex`,
            return_url:  successUrl,
            items: [{
              image:       "",
              description: `${nombreServicio} (${conceptoPago})`,
              quantity:    1,
              price:       montoACobrar,
            }],
            metadata: metaMeta,
            options:  { button: false, redirect: true },
          }),
        });
        const mobbexData = await mobbexRes.json();
        if (mobbexData?.data?.url) {
          return res.json({ payment_url: mobbexData.data.url, monto: montoACobrar, pasarela: "mobbex" });
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

        const response = await pref.create({
          body: {
            items: [{
              title:      `${nombreServicio} (${conceptoPago}): ${fecha} - ${hora}hs`,
              unit_price: montoACobrar,
              quantity:   1,
              currency_id: "ARS",
            }],
            metadata:         { ...metaMeta, tipo_pago: metodo },
            notification_url: `${API_URL}/webhook/mp`,
            back_urls: { success: successUrl, failure: cancelUrl, pending: cancelUrl },
            auto_return: "approved",
          },
        });

        return res.json({ payment_url: response.init_point, monto: montoACobrar, pasarela: "mercadopago" });
      } catch (e) {
        return res.status(500).json({ success: false, error: "Error con MercadoPago." });
      }
    }

    res.status(400).json({ success: false, error: "Sin pasarela de pago configurada." });
  } catch (e) {
    console.error("Error en /api/create-preference:", e.message);
    res.status(500).json({ success: false, error: e.message });
  }
});


// ══════════════════════════════════════════════════════════════
// OAUTH — Mercado Pago
// ══════════════════════════════════════════════════════════════

app.get("/oauth-callback", async (req, res) => {
  const { code, state: dominio } = req.query;
  if (!code || !dominio) return res.status(400).send("Parámetros inválidos.");

  try {
    const dominioClean = cleanDominio(dominio);
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
    const data     = await response.json();
    const panelUrl = process.env.PANEL_URL || "https://negosocio.framer.website/panel";

    if (data.access_token) {
      await supabase.from("usuarios").update({ mp_access_token: data.access_token }).eq("dominio", dominioClean);
      invalidateCache(dominioClean);
      return res.redirect(`${panelUrl}?status=mp_success&u=${dominioClean}`);
    }
    res.redirect(`${panelUrl}?status=mp_error&u=${dominioClean}`);
  } catch (e) {
    res.status(500).send("Error al vincular Mercado Pago.");
  }
});


// ══════════════════════════════════════════════════════════════
// WEBHOOKS
// ══════════════════════════════════════════════════════════════

async function procesarPagoConfirmado({ dominio, nombre, telefono, email, fecha, hora, servicio_id, servicio_nombre, monto, moneda, metodo_pago, payment_id, estado }) {
  let turnoId = null;

  if (estado === "aprobado") {
    let precioCobrado = monto;

    const { data: turnoInsertado } = await supabase.from("turnos").insert([{
      dominio,
      nombre:          nombre?.trim() || "Cliente",
      telefono:        cleanPhone(telefono?.toString() || "0"),
      email:           email?.trim().toLowerCase() || null,
      fecha,
      hora,
      servicio_id:     servicio_id || null,
      servicio_nombre: servicio_nombre || null,
      precio_cobrado:  precioCobrado,
      estado:          "confirmado",
      metodo_pago,
      payment_id:      String(payment_id),
    }]).select().single();

    turnoId = turnoInsertado?.id || null;

    const { data: userNegocio } = await supabase.from("usuarios").select("email").eq("dominio", dominio).single();
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
    dominio,
    turno_id:         turnoId,
    fecha_turno:      fecha,
    fecha_pago:       new Date().toISOString(),
    monto,
    moneda:           moneda || "ARS",
    metodo_pago,
    estado,
    nombre_cliente:   nombre?.trim() || "Cliente",
    email_cliente:    email?.trim()  || null,
    telefono_cliente: cleanPhone(telefono?.toString() || ""),
    servicio_id:      servicio_id    || null,
    servicio_nombre:  servicio_nombre || null,
    payment_id:       String(payment_id),
  }]);

  invalidateCache(dominio);
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
      const dominio = cleanDominio(payData.metadata?.dominio || payData.metadata?.slug || "");
      if (!dominio) return res.sendStatus(200);

      const { data: userNegocio } = await supabase.from("usuarios").select("mp_access_token").eq("dominio", dominio).single();
      let meta = payData.metadata;
      if (userNegocio?.mp_access_token) {
        const real = await fetch(`https://api.mercadopago.com/v1/payments/${paymentId}`, {
          headers: { Authorization: `Bearer ${userNegocio.mp_access_token}` },
        });
        meta = (await real.json()).metadata;
      }

      const estado = payData.status === "approved" ? "aprobado" : payData.status === "pending" ? "pendiente" : "rechazado";
      await procesarPagoConfirmado({
        dominio,
        nombre:          meta.nombre,
        telefono:        meta.telefono,
        email:           meta.email,
        fecha:           meta.fecha,
        hora:            meta.hora,
        servicio_id:     meta.servicio_id    || null,
        servicio_nombre: meta.servicio_nombre || null,
        monto:           Number(payData.transaction_amount || 0),
        moneda:          payData.currency_id || "ARS",
        metodo_pago:     "mercadopago",
        payment_id:      paymentId,
        estado,
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
    const dominio    = cleanDominio(meta.dominio || meta.slug || "");
    const monto      = Number(body.total || 0);
    const paymentId  = body.id || body.payment?.id || "mobbex-" + Date.now();

    if (!dominio) return res.sendStatus(200);

    await procesarPagoConfirmado({
      dominio,
      nombre:          meta.nombre,
      telefono:        meta.telefono,
      email:           meta.email,
      fecha:           meta.fecha,
      hora:            meta.hora,
      servicio_id:     meta.servicio_id    || null,
      servicio_nombre: meta.servicio_nombre || null,
      monto,
      moneda:          "ARS",
      metodo_pago:     "mobbex",
      payment_id:      paymentId,
      estado,
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
  ║   NegoSocio API v7.0                         ║
  ║   Identificador: dominio web del cliente     ║
  ║   Precio: por servicio                       ║
  ║   Sin comisiones de plataforma               ║
  ║   Puerto: ${PORT}                              ║
  ╚═══════════════════════════════════════════════╝
  `);
});

export default app;
