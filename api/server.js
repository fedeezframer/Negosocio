import express        from "express";
import cors           from "cors";
import { createClient } from "@supabase/supabase-js";
import { MercadoPagoConfig, Preference } from "mercadopago";
import fetch          from "node-fetch";
import bcrypt         from "bcryptjs";
import jwt            from "jsonwebtoken";
import rateLimit      from "express-rate-limit";
import multer         from "multer";
import crypto         from "crypto";

// ══════════════════════════════════════════════════════════════
// CONFIGURACIÓN GLOBAL
// ══════════════════════════════════════════════════════════════
const app = express();
app.set("trust proxy", 1);

// FIX-SEC: APPS_SCRIPT_URL sacada del código fuente y movida a env var.
// Antes estaba hardcodeada -> si el repo se filtra, cualquiera puede
// pegarle a ese endpoint de Apps Script.
const APPS_SCRIPT_URL = process.env.APPS_SCRIPT_URL || "";
if (!APPS_SCRIPT_URL) {
  console.warn("⚠️  APPS_SCRIPT_URL no configurada. Los mails (bienvenida, códigos, turnos, etc.) no se van a enviar.");
}

const BCRYPT_ROUNDS  = 10;
const CACHE_DURATION = 20_000;
// FIX-SEC: JWT de 7 días bajado a 1 día. Reduce la ventana de exposición
// si un token se filtra (XSS, dispositivo compartido, etc).
const JWT_EXPIRY     = process.env.JWT_EXPIRY || "1d";
const API_URL        = process.env.API_URL || "https://negosocio.onrender.com";

const DIAS_PRUEBA        = parseInt(process.env.DIAS_PRUEBA       || "15");
const PRECIO_RENOVACION  = parseInt(process.env.PRECIO_RENOVACION || "19000");
const MP_PLATFORM_TOKEN  = process.env.MP_PLATFORM_TOKEN          || "";
// FIX-SEC: secret propio para validar la firma de los webhooks de MP.
const MP_WEBHOOK_SECRET  = process.env.MP_WEBHOOK_SECRET          || "";
const PANEL_URL          = process.env.PANEL_URL                  || "https://turnits.com/panel";
const SUCCESS_URL        = process.env.SUCCESS_URL                || "https://turnits.com/success";
const ERROR_URL          = process.env.ERROR_URL                  || "https://turnits.com/error";
const RENOVACION_SUCCESS = process.env.RENOVACION_SUCCESS_URL     || `${PANEL_URL}?status=renovacion_ok`;
const RENOVACION_CANCEL  = process.env.RENOVACION_CANCEL_URL      || `${PANEL_URL}?status=renovacion_cancel`;

// FIX-SEC: orígenes permitidos para el panel/admin (CORS restringido).
// El widget público de reservas sigue abierto (lo necesita, corre en
// el sitio de cada negocio en Framer). Las rutas de panel/admin en cambio
// solo deberían aceptar pedidos desde tu propio dominio.
const PANEL_ORIGINS = (process.env.PANEL_ORIGINS || "https://turnits.com,https://www.turnits.com")
  .split(",").map((o) => o.trim()).filter(Boolean);

const CBU_REGEX   = /^\d{22}$/;
const ALIAS_REGEX = /^[a-zA-Z0-9._-]{6,30}$/;

const REPROGRAMAR_URL = process.env.REPROGRAMAR_URL || "https://turnits.com/reprogramar";
 
function validarDatosBancarios(d) {
  if (typeof d !== "object" || d === null || Array.isArray(d)) return false;
  const { banco, titular, cbu, alias } = d;
  if (banco    !== undefined && (typeof banco    !== "string" || banco.length    > 60)) return false;
  if (titular  !== undefined && (typeof titular  !== "string" || titular.length  > 80)) return false;
  if (cbu   !== undefined && cbu   !== "" && !CBU_REGEX.test(cbu))     return false;
  if (alias !== undefined && alias !== "" && !ALIAS_REGEX.test(alias)) return false;
  return true;
}

function tokenDeGestionValido(tokenRecibido, tokenReal) {
  if (!tokenRecibido || !tokenReal) return false;
  const a = Buffer.from(String(tokenRecibido));
  const b = Buffer.from(String(tokenReal));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

// ══════════════════════════════════════════════════════════════
// WHATSAPP CLOUD API — Config
// Notificaciones de turno por WhatsApp usando la Cloud API oficial
// de Meta, con UN número propio de Turnits (igual que Apps Script
// manda los mails para todos los negocios).
//
// Variables de entorno necesarias en Render:
//   WHATSAPP_TOKEN              → access token permanente del WABA de Turnits
//   WHATSAPP_PHONE_NUMBER_ID    → phone_number_id del número emisor (Meta Business Suite)
//   WHATSAPP_VERIFY_TOKEN       → string propio, cualquiera, para el handshake del webhook
//   WHATSAPP_TEMPLATE_TURNO     → nombre de la plantilla aprobada (default: "confirmacion_turno")
//   WHATSAPP_TEMPLATE_LISTA_ESPERA → nombre de la plantilla de aviso de cupo liberado (default: "turno_liberado")
//   WHATSAPP_API_VERSION        → versión de Graph API (default: "v21.0")
//   WHATSAPP_DEFAULT_COUNTRY    → prefijo a anteponer si el teléfono no lo trae (default: "549" = Arg. móvil)
//
// La plantilla "confirmacion_turno" debe crearse y aprobarse antes
// en Meta Business Manager. Este helper asume 4 variables en el
// body, en este orden: {{1}} nombre cliente, {{2}} nombre negocio,
// {{3}} servicio, {{4}} fecha y hora. Si tu plantilla aprobada
// tiene otro texto/orden, ajustá los "parameters" de enviarWhatsappTurno().
// ══════════════════════════════════════════════════════════════
const WHATSAPP_TOKEN                = process.env.WHATSAPP_TOKEN                || "";
const WHATSAPP_PHONE_NUMBER_ID      = process.env.WHATSAPP_PHONE_NUMBER_ID      || "";
const WHATSAPP_VERIFY_TOKEN         = process.env.WHATSAPP_VERIFY_TOKEN         || "";
const WHATSAPP_TEMPLATE_TURNO       = process.env.WHATSAPP_TEMPLATE_TURNO       || "confirmacion_turno";
const WHATSAPP_TEMPLATE_LISTA_ESPERA = process.env.WHATSAPP_TEMPLATE_LISTA_ESPERA || "turno_liberado";
const WHATSAPP_API_VERSION          = process.env.WHATSAPP_API_VERSION          || "v21.0";
const WHATSAPP_DEFAULT_COUNTRY      = process.env.WHATSAPP_DEFAULT_COUNTRY      || "549";
const WHATSAPP_HABILITADO           = !!(WHATSAPP_TOKEN && WHATSAPP_PHONE_NUMBER_ID);

if (!WHATSAPP_HABILITADO) {
  console.warn("⚠️  WhatsApp Cloud API no configurada (faltan WHATSAPP_TOKEN / WHATSAPP_PHONE_NUMBER_ID). Notificaciones por WhatsApp deshabilitadas.");
}

// ══════════════════════════════════════════════════════════════
// MULTER
// FIX-SEC: se restringe el tipo de archivo a nivel de fileFilter,
// además del límite de tamaño que ya existía. No se acepta SVG
// (puede llevar <script> embebido -> XSS almacenado).
// ══════════════════════════════════════════════════════════════
const TIPOS_IMAGEN_PERMITIDOS = ["image/jpeg", "image/png", "image/webp"];
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 3 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (!TIPOS_IMAGEN_PERMITIDOS.includes(file.mimetype)) {
      return cb(new Error("Formato de imagen no permitido. Usá JPG, PNG o WEBP."));
    }
    cb(null, true);
  },
});

// ══════════════════════════════════════════════════════════════
// SUPABASE
// FIX: priorizar la service role key explícita. Este backend hace
// updates/deletes/storage admin, así que NUNCA debe usarse la anon key.
// Si en Render solo existe SUPABASE_KEY (nombre viejo), se usa como
// fallback para no romper el deploy actual, pero conviene migrar
// la variable a SUPABASE_SERVICE_ROLE_KEY cuanto antes.
// ══════════════════════════════════════════════════════════════
const SUPABASE_SECRET = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_KEY;
if (!process.env.SUPABASE_SERVICE_ROLE_KEY) {
  console.warn("⚠️  Usando SUPABASE_KEY como fallback. Migrar a SUPABASE_SERVICE_ROLE_KEY y verificar que sea la service role, no la anon key.");
}
const supabase = createClient(process.env.SUPABASE_URL, SUPABASE_SECRET);

// ══════════════════════════════════════════════════════════════
// HELPERS
// ══════════════════════════════════════════════════════════════
const cleanSlug = (raw) => {
  if (!raw) return "";
  return raw.toLowerCase().trim()
    .normalize("NFD").replace(/[\u0300-\u036f]/g, "")
    .replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
};

const isActivo = (val) => val === "true" || val === true;

async function generarSlugUnico(businessName) {
  const base = cleanSlug(businessName);
  let slug = base, n = 2;
  while (true) {
    const { data } = await supabase.from("usuarios").select("id").eq("slug", slug).maybeSingle();
    if (!data) break;
    slug = `${base}-${n++}`;
  }
  return slug;
}

const validateEmail    = (e) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);
const validatePassword = (p) => p && p.length >= 6;
const validatePhone    = (p) => /^[0-9]{7,15}$/.test(p.toString().replace(/\s/g, ""));
const cleanPhone = (p) => p.toString().replace(/\s/g, "").replace(/^\+/, "").trim();

// FIX-SEC: helper de sanitización estricta para valores que van a
// construirse dentro de filtros PostgREST (.or()). Rechaza cualquier
// caracter que no sea alfanumérico, @, ., -, _  -> evita que un email
// o teléfono "creativo" (ej: "a,id.gt.0@x.co") altere la sintaxis del
// filtro e inyecte condiciones extra (equivalente a SQL injection en
// la capa de filtros de Supabase).
const esValorSeguroParaFiltro = (v) => /^[a-zA-Z0-9@._-]+$/.test(v);

const calcularVencimiento = (diasExtra = 30, baseISO = null) => {
  const base = baseISO ? new Date(baseISO + "T12:00:00-03:00") : new Date();
  base.setDate(base.getDate() + diasExtra);
  return base.toISOString().split("T")[0];
};

const diasHastaVencer = (fechaISO) => {
  const hoy   = new Date(new Date().toLocaleString("en-US", { timeZone: "America/Argentina/Buenos_Aires" }));
  const vence = new Date(fechaISO + "T23:59:59-03:00");
  return Math.ceil((vence - hoy) / (1000 * 60 * 60 * 24));
};

// Determina si una fecha es día laboral (según horarios + excepciones). Devuelve la config del día o null.
function obtenerIntervalosDia(horarios, excepciones, fecha) {
  const excepcionesArr = excepciones || [];
  const excDelDia = Array.isArray(excepcionesArr)
    ? excepcionesArr.find((e) => (typeof e === "string" ? e === fecha : e?.fecha === fecha))
    : null;
  const excType = typeof excDelDia === "string" ? "block" : excDelDia?.type;

  if (excType === "block") return null;

  const toMin = (t) => { if (!t) return null; const [h, m] = t.split(":").map(Number); return h * 60 + m; };

  // Excepción con intervalos propios para ESTA fecha puntual
  if (excType === "custom") {
    const intervalos = (excDelDia?.slots || [])
      .map(([desde, hasta]) => [toMin(desde), toMin(hasta)])
      .filter(([ini, fin]) => ini != null && fin != null && fin > ini);
    return intervalos.length ? intervalos : null;
  }

  // Sin excepción: horario semanal recurrente de ese día
  const diasSemana = ["domingo", "lunes", "martes", "miercoles", "jueves", "viernes", "sabado"];
  const diaConfig = horarios?.[diasSemana[new Date(fecha + "T12:00:00").getDay()]];
  if (!diaConfig?.activo) return null;

  const inicioJornada = toMin(diaConfig.jornada?.[0]);
  const finJornada    = toMin(diaConfig.jornada?.[1]);
  if (inicioJornada == null || finJornada == null || finJornada <= inicioJornada) return null;

  const dIni = toMin(diaConfig.descanso?.[0]);
  const dFin = toMin(diaConfig.descanso?.[1]);

  if (dIni != null && dFin != null && dFin > dIni) {
    const intervalos = [];
    if (dIni > inicioJornada) intervalos.push([inicioJornada, dIni]);
    if (finJornada > dFin)    intervalos.push([dFin, finJornada]);
    return intervalos;
  }
  return [[inicioJornada, finJornada]];
}

// ══════════════════════════════════════════════════════════════
// VALIDACIÓN DE ESTRUCTURA: horarios / excepciones
// FIX-SEC: antes /settings/:slug guardaba "horarios" y "excepciones"
// tal cual venían del body, sin validar forma. Un valor malformado
// no rompe la DB pero rompe silenciosamente el cálculo de slots.
// Estas funciones validan la forma esperada antes de guardar.
// ══════════════════════════════════════════════════════════════
const HORA_REGEX = /^([01]\d|2[0-3]):([0-5]\d)$/;
const DIAS_SEMANA_VALIDOS = ["domingo", "lunes", "martes", "miercoles", "jueves", "viernes", "sabado"];

function validarHorarios(horarios) {
  if (typeof horarios !== "object" || horarios === null || Array.isArray(horarios)) return false;
  for (const [dia, config] of Object.entries(horarios)) {
    if (!DIAS_SEMANA_VALIDOS.includes(dia)) return false;
    if (typeof config !== "object" || config === null) return false;
    if (typeof config.activo !== "boolean") return false;
    if (config.activo) {
      if (!Array.isArray(config.jornada) || config.jornada.length !== 2) return false;
      if (!config.jornada.every((h) => HORA_REGEX.test(h))) return false;
      if (config.descanso !== undefined && config.descanso !== null) {
        if (!Array.isArray(config.descanso) || config.descanso.length !== 2) return false;
        if (!config.descanso.every((h) => HORA_REGEX.test(h))) return false;
      }
    }
  }
  return true;
}

function validarExcepciones(excepciones) {
  if (!Array.isArray(excepciones)) return false;
  const FECHA_REGEX = /^\d{4}-\d{2}-\d{2}$/;
  return excepciones.every((exc) => {
    if (typeof exc === "string") return FECHA_REGEX.test(exc);
    if (typeof exc !== "object" || exc === null) return false;
    if (!FECHA_REGEX.test(exc.fecha || "")) return false;
    if (!["block", "custom"].includes(exc.type)) return false;
    if (exc.type === "custom") {
      if (!Array.isArray(exc.slots)) return false;
      return exc.slots.every((s) => Array.isArray(s) && s.length === 2 && s.every((h) => HORA_REGEX.test(h)));
    }
    return true;
  });
}

function horaDentroDeIntervalos(horarios, excepciones, fecha, hora) {
  const intervalos = obtenerIntervalosDia(horarios, excepciones, fecha);
  if (!intervalos) return false;
  const [h, m] = hora.split(":").map(Number);
  const minutos = h * 60 + m;
  return intervalos.some(([ini, fin]) => minutos >= ini && minutos < fin);
}

// ══════════════════════════════════════════════════════════════
// HELPER: NOTIFICACIONES IN-APP (bandeja de entrada del panel)
// Inserta una fila en `notificaciones`. Nunca bloquea el flujo
// principal: si falla, solo se loguea.
// ══════════════════════════════════════════════════════════════
async function crearNotificacion({ slug, tipo, titulo, mensaje, data = {} }) {
  try {
    const { error } = await supabase.from("notificaciones").insert([{
      slug, tipo, titulo, mensaje, data,
    }]);
    if (error) console.error("Error creando notificación:", error.message);
  } catch (e) {
    console.error("Error creando notificación:", e.message);
  }
}

// ══════════════════════════════════════════════════════════════
// HELPER: TIPS DE BUENAS PRÁCTICAS (bandeja de entrada)
// ══════════════════════════════════════════════════════════════
async function generarTips(slug) {
  try {
    const [{ data: user }, { data: servicios }] = await Promise.all([
      supabase.from("usuarios").select("mp_access_token, logo_url, created_at").eq("slug", slug).maybeSingle(),
      supabase.from("servicios").select("id").eq("slug", slug).limit(1),
    ]);
    if (!user) return;

    const yaExiste = async (clave) => {
      const { data } = await supabase.from("notificaciones")
        .select("id").eq("slug", slug).eq("tipo", "tip")
        .contains("data", { clave }).maybeSingle();
      return !!data;
    };

    if (!user.mp_access_token && !(await yaExiste("conectar_mp"))) {
      await crearNotificacion({
        slug, tipo: "tip",
        titulo: "Te recomendamos conectar Mercado Pago",
        mensaje: "Con un método de pago activo (seña o pago total) reducís el ausentismo: los clientes que pagan casi no faltan.",
        data: { clave: "conectar_mp" },
      });
    }

    if ((!servicios || servicios.length === 0) && !(await yaExiste("cargar_servicios"))) {
      await crearNotificacion({
        slug, tipo: "tip",
        titulo: "Cargá tus servicios",
        mensaje: "Definir servicios con precio y duración hace que la reserva sea más rápida y clara para tus clientes.",
        data: { clave: "cargar_servicios" },
      });
    }

    if (!user.logo_url && !(await yaExiste("subir_logo"))) {
      await crearNotificacion({
        slug, tipo: "tip",
        titulo: "Sumá tu logo",
        mensaje: "Un logo propio le da más confianza a tus clientes al momento de reservar.",
        data: { clave: "subir_logo" },
      });
    }
  } catch (e) {
    console.error("Error generando tips:", e.message);
  }
}

// Notifica al primero en la lista de espera cuando se libera un cupo
async function notificarListaEspera(slug, fecha) {
  const { data: pendientes } = await supabase.from("lista_espera")
    .select("*").eq("slug", slug).eq("fecha", fecha).eq("estado", "pendiente")
    .order("created_at", { ascending: true }).limit(1);
  if (!pendientes?.length) return;

  const entrada = pendientes[0];
  const { data: user } = await supabase.from("usuarios").select("business_name").eq("slug", slug).maybeSingle();

  if ((entrada.canal_aviso === "email" || entrada.canal_aviso === "ambos") && entrada.email && APPS_SCRIPT_URL) {
    fetch(APPS_SCRIPT_URL, {
      method: "POST", headers: { "Content-Type": "text/plain" },
      body: JSON.stringify({
        action: "turnoLiberado", emailCliente: entrada.email, nombreCliente: entrada.nombre,
        businessName: user?.business_name || "", fecha, slug,
      }),
    }).catch((e) => console.error("Error mail lista de espera:", e.message));
  }

  if ((entrada.canal_aviso === "whatsapp" || entrada.canal_aviso === "ambos") && entrada.telefono) {
    enviarWhatsapp(entrada.telefono, WHATSAPP_TEMPLATE_LISTA_ESPERA, [
      { type: "body", parameters: [
        { type: "text", text: entrada.nombre.slice(0, 60) },
        { type: "text", text: (user?.business_name || "").slice(0, 60) },
        { type: "text", text: fecha },
      ]},
    ]).catch((e) => console.error("Error whatsapp lista de espera:", e.message));
  }

  await supabase.from("lista_espera").update({ estado: "notificado" }).eq("id", entrada.id);

  crearNotificacion({
    slug,
    tipo: "lista_espera",
    titulo: "Se avisó un cupo liberado",
    mensaje: `${entrada.nombre} fue notificado/a por ${entrada.canal_aviso} sobre un cupo libre el ${fecha}.`,
    data: { fecha },
  });
}

async function verificarPassword(passwordIngresado, passwordGuardado, userId) {
  const stored   = String(passwordGuardado);
  const esBcrypt = /^\$2[aby]\$/.test(stored);
  if (esBcrypt) return await bcrypt.compare(String(passwordIngresado), stored);
  const ok = stored === String(passwordIngresado);
  if (ok) {
    const hash = await bcrypt.hash(String(passwordIngresado), BCRYPT_ROUNDS);
    await supabase.from("usuarios").update({ password: hash }).eq("id", userId);
    console.log(`🔄 Password migrado a bcrypt: user ${userId}`);
  }
  return ok;
}

// ══════════════════════════════════════════════════════════════
// CACHÉ EN MEMORIA
// ══════════════════════════════════════════════════════════════
const globalCache = {};
const invalidateCache = (slug) => { delete globalCache[slug]; };

// ══════════════════════════════════════════════════════════════
// FIX-SEC: bloqueo de fuerza bruta por CUENTA (además del rate
// limit por IP que ya existía). Cuenta intentos fallidos de login
// por email/slug en memoria y bloquea temporalmente tras 8 intentos
// en 15 minutos. Es en memoria (no persiste un redeploy), pero corta
// el caso real: un atacante insistiendo contra una cuenta puntual
// aunque rote de IP.
// ══════════════════════════════════════════════════════════════
const intentosFallidosLogin = new Map(); // key -> { intentos, primerIntento, bloqueadoHasta }
const MAX_INTENTOS_LOGIN   = 8;
const VENTANA_INTENTOS_MS  = 15 * 60 * 1000;
const BLOQUEO_MS           = 15 * 60 * 1000;

function chequearBloqueoLogin(key) {
  const registro = intentosFallidosLogin.get(key);
  if (!registro) return { bloqueado: false };
  if (registro.bloqueadoHasta && Date.now() < registro.bloqueadoHasta) {
    return { bloqueado: true, minutosRestantes: Math.ceil((registro.bloqueadoHasta - Date.now()) / 60000) };
  }
  return { bloqueado: false };
}

function registrarIntentoFallidoLogin(key) {
  const ahora = Date.now();
  let registro = intentosFallidosLogin.get(key);
  if (!registro || ahora - registro.primerIntento > VENTANA_INTENTOS_MS) {
    registro = { intentos: 0, primerIntento: ahora, bloqueadoHasta: null };
  }
  registro.intentos += 1;
  if (registro.intentos >= MAX_INTENTOS_LOGIN) {
    registro.bloqueadoHasta = ahora + BLOQUEO_MS;
  }
  intentosFallidosLogin.set(key, registro);
}

function limpiarIntentosLogin(key) {
  intentosFallidosLogin.delete(key);
}

// ══════════════════════════════════════════════════════════════
// RATE LIMITING
// FIX-SEC: se agrega limiterCodigo, más estricto, para los endpoints
// de códigos numéricos de 6 dígitos (antes solo tenían el límite
// global de 200/min, que permite fuerza bruta sobre 1.000.000 de
// combinaciones en tiempo razonable).
// ══════════════════════════════════════════════════════════════
const limiterAuth    = rateLimit({ windowMs: 15 * 60 * 1000, max: 20,  message: "Demasiados intentos.",  standardHeaders: true, legacyHeaders: false });
const limiterBooking = rateLimit({ windowMs: 60 * 1000,       max: 20,  message: "Demasiadas reservas." });
const limiterAPI     = rateLimit({ windowMs: 60 * 1000,       max: 200 });
const limiterCodigo  = rateLimit({ windowMs: 15 * 60 * 1000, max: 10,  message: "Demasiados intentos. Probá de nuevo en unos minutos.", standardHeaders: true, legacyHeaders: false });

// ══════════════════════════════════════════════════════════════
// MIDDLEWARES
// FIX-SEC: CORS separado. Las rutas públicas (widget de reserva)
// siguen abiertas a "*", pero las rutas de panel/admin (definidas
// más abajo con requireAuth / requireAdminKey) exigen que el Origin
// esté en PANEL_ORIGINS. Esto reduce el impacto de un eventual robo
// de JWT vía XSS: un sitio de terceros no puede usar el token desde
// el navegador de la víctima contra las rutas sensibles (CORS no
// protege contra un atacante pegándole directo a la API con curl,
// pero sí contra el escenario más común de robo-y-uso-desde-otro-sitio).
// ══════════════════════════════════════════════════════════════
app.use(cors({
  origin: "*",
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization", "x-api-key"],
}));

const corsPanel = cors({
  origin: (origin, cb) => {
    // Permite llamadas sin Origin (ej. Postman, server-to-server, cron)
    if (!origin || PANEL_ORIGINS.includes(origin)) return cb(null, true);
    cb(new Error("Origen no permitido."));
  },
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization", "x-api-key"],
});

app.use(express.json({ limit: "10mb" }));
app.use(limiterAPI);

// ══════════════════════════════════════════════════════════════
// MIDDLEWARE: JWT AUTH
// ══════════════════════════════════════════════════════════════
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
    if (payload.rol === "superadmin") { req.auth = payload; return next(); }
    const slugRuta = cleanSlug(req.params.slug || req.body?.slug || req.query?.slug || "");
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
// MIDDLEWARE: ADMIN KEY
// FIX-SEC: comparación en tiempo constante (crypto.timingSafeEqual)
// en vez de "===", para no filtrar por timing cuánto del secret
// coincide. Requiere que ambos buffers tengan el mismo largo, por
// eso se compara el largo primero (si difiere, ya es inválido).
// ══════════════════════════════════════════════════════════════
const requireAdminKey = (req, res, next) => {
  const key = req.headers["x-api-key"] || "";
  const secret = process.env.ADMIN_SECRET || "";
  if (!secret) return res.status(401).json({ success: false, error: "No autorizado." });

  const keyBuf    = Buffer.from(String(key));
  const secretBuf = Buffer.from(secret);
  const valido = keyBuf.length === secretBuf.length && crypto.timingSafeEqual(keyBuf, secretBuf);

  if (!valido) return res.status(401).json({ success: false, error: "No autorizado." });
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

function agruparPagos(turnos, hoyISO) {
  const porDia = {}, porSemana = {}, porMes = {};
  const porEstado = { aprobado: 0, pendiente: 0, rechazado: 0 };
  const clientesSet = new Set();
  let volumenTotal = 0, cantidadTotal = 0;

  turnos.forEach((t) => {
    const fecha  = (t.fecha_pago || t.created_at || hoyISO).toString().split("T")[0];
    const monto  = Number(t.monto_pagado || 0);
    const estado = t.pago_estado || "sin_pago";
    if (estado === "sin_pago") return;

    const [va, vm, vd] = fecha.split("-").map(Number);
    const semKey = `${va}-S${Math.ceil(vd / 7)}`;
    const mesKey = `${va}-${String(vm).padStart(2, "0")}`;

    if (!porDia[fecha])     porDia[fecha]     = { volumen: 0, cantidad: 0, aprobado: 0, pendiente: 0, rechazado: 0 };
    if (!porSemana[semKey]) porSemana[semKey] = { label: semKey, volumen: 0, cantidad: 0 };
    if (!porMes[mesKey])    porMes[mesKey]    = { label: mesKey, volumen: 0, cantidad: 0 };

    porDia[fecha].volumen      += monto;
    porDia[fecha].cantidad     += 1;
    porDia[fecha][estado]       = (porDia[fecha][estado] || 0) + 1;
    porSemana[semKey].volumen  += monto; porSemana[semKey].cantidad += 1;
    porMes[mesKey].volumen     += monto; porMes[mesKey].cantidad    += 1;
    porEstado[estado]           = (porEstado[estado] || 0) + 1;

    if (t.email)         clientesSet.add(t.email.toLowerCase());
    else if (t.telefono) clientesSet.add(t.telefono);

    if (estado === "aprobado") { volumenTotal += monto; cantidadTotal += 1; }
  });

  return {
    porDia,
    porSemana:      Object.values(porSemana).sort((a, b) => a.label.localeCompare(b.label)),
    porMes:         Object.values(porMes).sort((a, b)    => a.label.localeCompare(b.label)),
    porEstado, volumenTotal, cantidadTotal,
    ticketPromedio: cantidadTotal > 0 ? Math.round(volumenTotal / cantidadTotal) : 0,
    clientesNuevos: clientesSet.size,
  };
}

// ══════════════════════════════════════════════════════════════
// HELPER: ENVIAR MAIL DE TURNO
// ══════════════════════════════════════════════════════════════
function enviarMailTurno({ adminEmail, emailCliente, nombreCliente, fechaHora, slug, servicio, precioTotal, montoOnline, metodoPago }) {
  if (!APPS_SCRIPT_URL) return;
  const panelUrl = `${PANEL_URL}?u=${slug}`;

  fetch(APPS_SCRIPT_URL, {
    method: "POST",
    headers: { "Content-Type": "text/plain" },
    body: JSON.stringify({
      action:        "newAppointmentEmail",
      nombreCliente,
      fechaHora,
      adminEmail,
      emailCliente:  emailCliente || "",
      slug,
      servicio:      servicio     || "",
      precioTotal:   precioTotal  || 0,
      montoOnline:   montoOnline  || 0,
      metodoPago:    metodoPago   || "none",
      panelUrl,
    }),
  }).catch((e) => console.error("Error mail turno admin:", e.message));

  if (emailCliente) {
    fetch(APPS_SCRIPT_URL, {
      method: "POST",
      headers: { "Content-Type": "text/plain" },
      body: JSON.stringify({
        action:        "newAppointmentEmailCliente",
        nombreCliente,
        fechaHora,
        emailCliente,
        slug,
        servicio:      servicio    || "",
        precioTotal:   precioTotal || 0,
        montoOnline:   montoOnline || 0,
        metodoPago:    metodoPago  || "none",
      }),
    }).catch((e) => console.error("Error mail turno cliente:", e.message));
  }
}

// ══════════════════════════════════════════════════════════════
// HELPER: AVISAR CONFLICTO DE SOBREVENTA AL ADMIN
// ══════════════════════════════════════════════════════════════
function enviarMailConflictoTurno({ adminEmail, nombreCliente, fechaHora, slug, payment_id, monto }) {
  if (!adminEmail || !APPS_SCRIPT_URL) return;
  fetch(APPS_SCRIPT_URL, {
    method: "POST",
    headers: { "Content-Type": "text/plain" },
    body: JSON.stringify({
      action: "turnoConflicto",
      adminEmail,
      nombreCliente,
      fechaHora,
      slug,
      payment_id,
      monto,
      panelUrl: `${PANEL_URL}?u=${slug}`,
    }),
  }).catch((e) => console.error("Error mail conflicto turno:", e.message));
}

// ══════════════════════════════════════════════════════════════
// HELPER: WHATSAPP — formatear teléfono a formato internacional
// ══════════════════════════════════════════════════════════════
function formatPhoneWhatsapp(telefono) {
  const limpio = cleanPhone(telefono?.toString() || "");
  if (!limpio) return null;
  if (limpio.startsWith(WHATSAPP_DEFAULT_COUNTRY)) return limpio;
  if (limpio.length > 11) return limpio;
  return `${WHATSAPP_DEFAULT_COUNTRY}${limpio.replace(/^0+/, "")}`;
}

// ══════════════════════════════════════════════════════════════
// HELPER: WHATSAPP — envío genérico de mensaje por plantilla
// ══════════════════════════════════════════════════════════════
async function enviarWhatsapp(to, templateName, components = [], languageCode = "es_AR") {
  if (!WHATSAPP_HABILITADO) return { skipped: true, error: "whatsapp_no_configurado" };

  const numero = formatPhoneWhatsapp(to);
  if (!numero) return { skipped: true, error: "sin_telefono" };

  try {
    const res = await fetch(
      `https://graph.facebook.com/${WHATSAPP_API_VERSION}/${WHATSAPP_PHONE_NUMBER_ID}/messages`,
      {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${WHATSAPP_TOKEN}`,
          "Content-Type":  "application/json",
        },
        body: JSON.stringify({
          messaging_product: "whatsapp",
          to: numero,
          type: "template",
          template: {
            name: templateName,
            language: { code: languageCode },
            components,
          },
        }),
      }
    );
    const data = await res.json();
    if (!res.ok) {
      console.error("❌ Error WhatsApp:", JSON.stringify(data));
      return { success: false, error: data };
    }
    return { success: true, data };
  } catch (e) {
    console.error("❌ Error enviando WhatsApp:", e.message);
    return { success: false, error: e.message };
  }
}

function enviarWhatsappTurno({ telefono, nombreCliente, businessName, fechaHora, servicio }) {
  if (!WHATSAPP_HABILITADO || !telefono) return;

  enviarWhatsapp(telefono, WHATSAPP_TEMPLATE_TURNO, [
    {
      type: "body",
      parameters: [
        { type: "text", text: (nombreCliente || "Cliente").toString().slice(0, 60) },
        { type: "text", text: (businessName  || "").toString().slice(0, 60) },
        { type: "text", text: (servicio      || "tu turno").toString().slice(0, 60) },
        { type: "text", text: (fechaHora     || "").toString().slice(0, 60) },
      ],
    },
  ]).then((r) => {
    if (r?.success) console.log(`📲 WhatsApp turno enviado a ${telefono}`);
  }).catch((e) => console.error("Error WhatsApp turno:", e.message));
}

// ══════════════════════════════════════════════════════════════
// RUTAS BASE
// ══════════════════════════════════════════════════════════════
app.get("/",       (_, res) => res.json({ status: "online", version: "13.8-sec", timestamp: new Date().toISOString() }));
app.get("/health", (_, res) => res.json({ status: "ok",     timestamp: new Date().toISOString() }));

// ══════════════════════════════════════════════════════════════
// REGISTRO — PASO 1
// POST /registro/iniciar
// ══════════════════════════════════════════════════════════════
app.post("/registro/iniciar", limiterAuth, async (req, res) => {
  try {
    const { nombre_persona, apellido, email, telefono, business_name, password, horarios, duracion_turno, plan } = req.body;

    if (!nombre_persona || !email || !password || !business_name)
      return res.status(400).json({ success: false, error: "Faltan campos obligatorios." });
    if (!validateEmail(email))
      return res.status(400).json({ success: false, error: "Email inválido." });
    if (!validatePassword(password))
      return res.status(400).json({ success: false, error: "La contraseña debe tener al menos 6 caracteres." });
    if (telefono && !validatePhone(cleanPhone(telefono)))
      return res.status(400).json({ success: false, error: "Teléfono inválido (7-15 dígitos)." });
    if (business_name.trim().length < 2)
      return res.status(400).json({ success: false, error: "El nombre del negocio es demasiado corto." });
    // FIX-SEC: nombre_persona / apellido / business_name ahora se validan
    // en largo y se recortan caracteres de control, para reducir el
    // riesgo de que texto libre malicioso termine en mails/paneles sin escapar.
    if (nombre_persona.trim().length > 80 || business_name.trim().length > 80 || (apellido && apellido.trim().length > 80)) {
      return res.status(400).json({ success: false, error: "Alguno de los campos es demasiado largo." });
    }
    // FIX-SEC: si mandan horarios en el registro, se valida la forma.
    if (horarios !== undefined && horarios !== null && !validarHorarios(horarios)) {
      return res.status(400).json({ success: false, error: "Formato de horarios inválido." });
    }

    const emailClean = email.trim().toLowerCase();

    const { data: yaExiste } = await supabase
      .from("usuarios").select("id").eq("email", emailClean).maybeSingle();
    if (yaExiste)
      return res.status(409).json({ success: false, error: "Ya existe una cuenta con ese email." });

    const password_hash = await bcrypt.hash(String(password), BCRYPT_ROUNDS);
    const codigo        = Math.floor(100000 + Math.random() * 900000).toString();
    const codigo_expiry = new Date(Date.now() + 1000 * 60 * 15).toISOString();

    const { error } = await supabase.from("registros_pendientes").upsert([{
      email:          emailClean,
      nombre_persona: nombre_persona.trim(),
      apellido:       apellido?.trim()       || null,
      telefono:       telefono ? cleanPhone(telefono) : null,
      business_name:  business_name.trim(),
      password_hash,
      plan:           plan === "premium" ? "premium" : "gratis",
      horarios:       horarios && typeof horarios === "object" ? horarios : null,
      duracion_turno: parseInt(duracion_turno) || 30,
      codigo,
      codigo_expiry,
    }], { onConflict: "email" });

    if (error) throw error;

    if (APPS_SCRIPT_URL) {
      fetch(APPS_SCRIPT_URL, {
        method: "POST", headers: { "Content-Type": "text/plain" },
        body: JSON.stringify({
          action: "verificarCodigo",
          email:  emailClean,
          nombre: nombre_persona.trim(),
          codigo,
        }),
      }).catch((e) => console.error("Error mail código:", e.message));
    }

    console.log(`📧 Código enviado a ${emailClean}`);
    res.json({ success: true, message: "Código enviado. Revisá tu email." });

  } catch (e) {
    console.error("Error en /registro/iniciar:", e.message);
    res.status(500).json({ success: false, error: "No se pudo iniciar el registro." });
  }
});

// ══════════════════════════════════════════════════════════════
// REGISTRO — PASO 2
// POST /registro/verificar
// FIX-SEC: agregado limiterCodigo (además de limiterAuth) para
// cortar fuerza bruta sobre el código de 6 dígitos.
// ══════════════════════════════════════════════════════════════
app.post("/registro/verificar", limiterAuth, limiterCodigo, async (req, res) => {
  try {
    const { email, codigo } = req.body;
    if (!email || !codigo)
      return res.status(400).json({ success: false, error: "Faltan email y código." });

    const emailClean = email.trim().toLowerCase();

    const { data: pendiente, error } = await supabase
      .from("registros_pendientes").select("*")
      .eq("email", emailClean).maybeSingle();

    if (error) throw error;
    if (!pendiente)
      return res.status(404).json({ success: false, error: "No hay un registro pendiente para ese email." });
    if (pendiente.codigo !== codigo.trim())
      return res.status(400).json({ success: false, error: "Código incorrecto." });
    if (new Date(pendiente.codigo_expiry) < new Date())
      return res.status(400).json({ success: false, error: "El código expiró. Iniciá el registro de nuevo." });

    const { data: yaExiste } = await supabase
      .from("usuarios").select("id").eq("email", emailClean).maybeSingle();
    if (yaExiste)
      return res.status(409).json({ success: false, error: "Ya existe una cuenta con ese email." });

    const slug              = await generarSlugUnico(pendiente.business_name);
    const planFinal         = pendiente.plan === "premium" ? "premium" : "gratis";
    const fechaVencimiento  = planFinal === "premium" ? calcularVencimiento(DIAS_PRUEBA) : null;
    const estadoSuscripcion = planFinal === "premium" ? "trial" : "activo";

    const insertData = {
      nombre_persona:     pendiente.nombre_persona,
      apellido:           pendiente.apellido           || null,
      email:              emailClean,
      telefono:           pendiente.telefono           || null,
      business_name:      pendiente.business_name,
      slug,
      password:           pendiente.password_hash,
      plan:               planFinal,
      metodo_pago:        "none",
      porcentaje_sena:    30,
      excepciones:        [],
      activo:             "true",
      email_verificado:   true,
      estado_suscripcion: estadoSuscripcion,
      fecha_vencimiento:  fechaVencimiento,
    };
    if (pendiente.horarios)       insertData.horarios       = pendiente.horarios;
    if (pendiente.duracion_turno) insertData.duracion_turno = pendiente.duracion_turno;

    const { data: nuevo, error: insertError } = await supabase
      .from("usuarios").insert([insertData])
      .select("id, slug, business_name, email, nombre_persona, plan, estado_suscripcion, fecha_vencimiento")
      .single();

    if (insertError) {
      if (insertError.code === "23505")
        return res.status(409).json({ success: false, error: "El email ya está registrado." });
      throw insertError;
    }

    await supabase.from("registros_pendientes").delete().eq("email", emailClean);

    if (APPS_SCRIPT_URL) {
      fetch(APPS_SCRIPT_URL, {
        method: "POST", headers: { "Content-Type": "text/plain" },
        body: JSON.stringify({
          action:      "bienvenida",
          adminEmail:  nuevo.email,
          nombre:      nuevo.nombre_persona,
          slug:        nuevo.slug,
          panel_url:   `${PANEL_URL}?u=${nuevo.slug}`,
          dias_prueba: planFinal === "premium" ? DIAS_PRUEBA : 0,
        }),
      }).catch((e) => console.error("Error mail bienvenida:", e.message));
    }

    crearNotificacion({
      slug: nuevo.slug,
      tipo: "sistema",
      titulo: "¡Bienvenido a Turnits!",
      mensaje: "Tu cuenta está lista. Configurá tus servicios y horarios para empezar a recibir turnos.",
      data: { clave: "bienvenida" },
    });
    generarTips(nuevo.slug);

    const secret = process.env.JWT_SECRET;
    const token  = secret
      ? jwt.sign({ slug: nuevo.slug, negocioId: nuevo.id, rol: "owner" }, secret, { expiresIn: JWT_EXPIRY })
      : null;

    console.log(`✅ Registro verificado y cuenta creada: ${slug}`);

    res.status(201).json({
      success:           true,
      slug:              nuevo.slug,
      business_name:     nuevo.business_name,
      plan:              nuevo.plan,
      panel_url:         `${PANEL_URL}?u=${nuevo.slug}`,
      token,
      dias_prueba:       planFinal === "premium" ? DIAS_PRUEBA : null,
      fecha_vencimiento: fechaVencimiento,
    });

  } catch (e) {
    console.error("Error en /registro/verificar:", e.message);
    res.status(500).json({ success: false, error: "No se pudo verificar el registro." });
  }
});

// ══════════════════════════════════════════════════════════════
// REGISTRO — Reenviar código
// POST /registro/reenviar-codigo
// ══════════════════════════════════════════════════════════════
app.post("/registro/reenviar-codigo", limiterAuth, async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ success: false, error: "Email requerido." });

    const emailClean = email.trim().toLowerCase();

    const { data: pendiente, error } = await supabase
      .from("registros_pendientes").select("nombre_persona")
      .eq("email", emailClean).maybeSingle();

    if (error) throw error;
    if (!pendiente)
      return res.status(404).json({ success: false, error: "No hay un registro pendiente para ese email." });

    const codigo        = Math.floor(100000 + Math.random() * 900000).toString();
    const codigo_expiry = new Date(Date.now() + 1000 * 60 * 15).toISOString();

    await supabase.from("registros_pendientes")
      .update({ codigo, codigo_expiry })
      .eq("email", emailClean);

    if (APPS_SCRIPT_URL) {
      fetch(APPS_SCRIPT_URL, {
        method: "POST", headers: { "Content-Type": "text/plain" },
        body: JSON.stringify({
          action: "verificarCodigo",
          email:  emailClean,
          nombre: pendiente.nombre_persona,
          codigo,
        }),
      }).catch((e) => console.error("Error reenvío código:", e.message));
    }

    res.json({ success: true, message: "Código reenviado." });

  } catch (e) {
    res.status(500).json({ success: false, error: "No se pudo reenviar el código." });
  }
});

// ══════════════════════════════════════════════════════════════
// TURNOS — Check cliente duplicado
// POST /turnos/check-cliente
// ══════════════════════════════════════════════════════════════
app.post("/turnos/check-cliente", limiterBooking, async (req, res) => {
  try {
    const { slug, email, telefono } = req.body;
    const slugClean = cleanSlug(slug || "");

    if (!slugClean || (!email && !telefono)) {
      return res.status(400).json({ success: false, error: "Faltan parámetros." });
    }

    const emailClean = email?.trim().toLowerCase();
    const phoneClean = telefono ? cleanPhone(telefono.toString()) : null;

    if (emailClean && !validateEmail(emailClean)) {
      return res.status(400).json({ success: false, error: "Email inválido." });
    }
    if (phoneClean && !validatePhone(phoneClean)) {
      return res.status(400).json({ success: false, error: "Teléfono inválido." });
    }

    const hoy = new Date().toISOString().split("T")[0];

    const [porEmail, porTelefono] = await Promise.all([
      emailClean
        ? supabase.from("turnos").select("id, email, telefono")
            .eq("slug", slugClean).gte("fecha", hoy).neq("estado", "cancelado").eq("email", emailClean)
        : Promise.resolve({ data: [] }),
      phoneClean
        ? supabase.from("turnos").select("id, email, telefono")
            .eq("slug", slugClean).gte("fecha", hoy).neq("estado", "cancelado").eq("telefono", phoneClean)
        : Promise.resolve({ data: [] }),
    ]);

    const turnos = [...(porEmail.data || []), ...(porTelefono.data || [])];
    const existe = turnos.length > 0;
    const coincide_email    = existe && !!emailClean && turnos.some(t => t.email?.toLowerCase() === emailClean);
    const coincide_telefono = existe && !!phoneClean && turnos.some(t => t.telefono === phoneClean);

    res.json({ success: true, existe, coincide_email, coincide_telefono });
  } catch (e) {
    console.error("Error en /turnos/check-cliente:", e.message);
    res.status(500).json({ success: false, error: "Error al verificar el cliente." });
  }
});

// ══════════════════════════════════════════════════════════════
// AUTH — LOGIN
// POST /login
// FIX-SEC: bloqueo temporal por cuenta tras varios intentos
// fallidos (además del rate limit por IP), y limpieza del contador
// al loguear con éxito.
// ══════════════════════════════════════════════════════════════
app.post("/login", limiterAuth, async (req, res) => {
  try {
    const rawSlug  = cleanSlug(req.body.slug || "");
    const email    = req.body.email?.trim().toLowerCase() || "";
    const password = req.body.password;

    if ((!rawSlug && !email) || !password) {
      return res.status(400).json({ success: false, error: "Faltan email (o slug) y contraseña." });
    }

    const claveBloqueo = rawSlug || email;
    const estadoBloqueo = chequearBloqueoLogin(claveBloqueo);
    if (estadoBloqueo.bloqueado) {
      return res.status(429).json({
        success: false,
        error: `Demasiados intentos fallidos. Probá de nuevo en ${estadoBloqueo.minutosRestantes} minuto(s).`,
      });
    }

    let query = supabase.from("usuarios")
      .select("id, slug, password, business_name, nombre_persona, apellido, email, activo, plan, estado_suscripcion, fecha_vencimiento");
    query = rawSlug ? query.eq("slug", rawSlug) : query.eq("email", email);

    const { data: user, error } = await query.maybeSingle();
    if (error) throw error;
    if (!user) {
      registrarIntentoFallidoLogin(claveBloqueo);
      return res.status(401).json({ success: false, error: "Credenciales incorrectas." });
    }

    const passwordOk = await verificarPassword(password, user.password, user.id);
    if (!passwordOk) {
      registrarIntentoFallidoLogin(claveBloqueo);
      return res.status(401).json({ success: false, error: "Credenciales incorrectas." });
    }

    limpiarIntentosLogin(claveBloqueo);

    const diasRestantes      = user.fecha_vencimiento ? diasHastaVencer(user.fecha_vencimiento) : null;
    const suscripcionVencida = diasRestantes !== null && diasRestantes <= 0;
    const esPremium          = user.plan === "premium";

    if (!isActivo(user.activo) && !suscripcionVencida) {
      return res.status(403).json({ success: false, error: "Este negocio está desactivado." });
    }

    const secret = process.env.JWT_SECRET;
    if (!secret) return res.status(500).json({ success: false, error: "JWT_SECRET no configurado." });

    const token = jwt.sign(
      { slug: user.slug, negocioId: user.id, rol: "owner" },
      secret, { expiresIn: JWT_EXPIRY }
    );

    const estadoSuscripcion = user.estado_suscripcion || "trial";

    if (suscripcionVencida && esPremium) {
      return res.json({
        success:        true,
        token,
        slug:           user.slug,
        business_name:  user.business_name,
        nombre_persona: user.nombre_persona,
        apellido:       user.apellido || "",
        email:          user.email,
        plan:           user.plan,
        redirect:       "renovar",
        suscripcion: {
          estado:            "suspendido",
          fecha_vencimiento: user.fecha_vencimiento,
          dias_restantes:    diasRestantes,
          vencida:           true,
        },
      });
    }

    res.json({
      success:        true,
      token,
      slug:           user.slug,
      business_name:  user.business_name,
      nombre_persona: user.nombre_persona,
      apellido:       user.apellido || "",
      email:          user.email,
      plan:           user.plan || "gratis",
      suscripcion: {
        estado:            suscripcionVencida ? "suspendido" : estadoSuscripcion,
        fecha_vencimiento: user.fecha_vencimiento,
        dias_restantes:    diasRestantes,
        alerta:            diasRestantes !== null && diasRestantes <= 5 && diasRestantes > 0,
        vencida:           suscripcionVencida,
      },
    });
  } catch (e) {
    console.error("Error en /login:", e.message);
    res.status(500).json({ success: false, error: "Error al iniciar sesión." });
  }
});

// ══════════════════════════════════════════════════════════════
// AUTH — VERIFY SESSION
// GET /verify-session
// ══════════════════════════════════════════════════════════════
app.get("/verify-session", async (req, res) => {
  try {
    const token = req.headers["authorization"]?.split(" ")[1] || req.query.token;
    if (!token) return res.json({ active: false, reason: "no_token" });

    const payload    = jwt.verify(token, process.env.JWT_SECRET);
    const { data: user } = await supabase.from("usuarios")
      .select("slug, business_name, email, nombre_persona, activo, plan, estado_suscripcion, fecha_vencimiento")
      .eq("slug", payload.slug).maybeSingle();

    if (!user || !isActivo(user.activo)) return res.json({ active: false, reason: "not_found" });

    const diasRestantes = user.fecha_vencimiento ? diasHastaVencer(user.fecha_vencimiento) : null;
    res.json({
      active:         true,
      slug:           user.slug,
      business_name:  user.business_name,
      email:          user.email,
      nombre_persona: user.nombre_persona,
      plan:           user.plan || "gratis",
      suscripcion: {
        estado:         user.estado_suscripcion,
        dias_restantes: diasRestantes,
        vencida:        diasRestantes !== null && diasRestantes <= 0,
      },
    });
  } catch (e) {
    res.json({ active: false, reason: "invalid_token" });
  }
});

// ══════════════════════════════════════════════════════════════
// ADMIN — RESETEAR PASSWORD
// POST /admin/reset-password
// ══════════════════════════════════════════════════════════════
app.post("/admin/reset-password", requireAdminKey, async (req, res) => {
  try {
    const { email, new_password } = req.body;
    if (!email || !new_password) return res.status(400).json({ success: false, error: "Faltan email y new_password." });
    if (!validatePassword(new_password)) return res.status(400).json({ success: false, error: "Mínimo 6 caracteres." });
    const hash = await bcrypt.hash(String(new_password), BCRYPT_ROUNDS);
    const { error } = await supabase.from("usuarios").update({ password: hash }).eq("email", email.trim().toLowerCase());
    if (error) throw error;
    res.json({ success: true, message: `Password actualizado para ${email}` });
  } catch (e) {
    res.status(500).json({ success: false, error: "No se pudo actualizar el password." });
  }
});

// ══════════════════════════════════════════════════════════════
// AUTH — Enviar código de verificación (por slug)
// POST /auth/send-code
// FIX-SEC: limiterCodigo agregado.
// ══════════════════════════════════════════════════════════════
app.post("/auth/send-code", limiterCodigo, async (req, res) => {
  try {
    const { slug } = req.body;
    if (!slug) return res.status(400).json({ success: false, error: "Slug requerido." });

    const codigo = Math.floor(100000 + Math.random() * 900000).toString();
    const expiry = new Date(Date.now() + 1000 * 60 * 15);

    const { data: user, error } = await supabase
      .from("usuarios")
      .update({ codigo_verificacion: codigo, codigo_verificacion_expiry: expiry.toISOString() })
      .eq("slug", cleanSlug(slug))
      .select("email, nombre_persona")
      .single();

    if (error) throw error;

    if (APPS_SCRIPT_URL) {
      fetch(APPS_SCRIPT_URL, {
        method: "POST",
        headers: { "Content-Type": "text/plain" },
        body: JSON.stringify({
          action: "verificarCodigo",
          email:  user.email,
          nombre: user.nombre_persona,
          codigo,
        }),
      }).catch((e) => console.error("Error mail código:", e.message));
    }

    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ success: false, error: "No se pudo enviar el código." });
  }
});

// ══════════════════════════════════════════════════════════════
// AUTH — Verificar código (por slug)
// POST /auth/verify-code
// FIX-SEC: limiterCodigo agregado.
// ══════════════════════════════════════════════════════════════
app.post("/auth/verify-code", limiterCodigo, async (req, res) => {
  try {
    const { slug, codigo } = req.body;
    if (!slug || !codigo) return res.status(400).json({ success: false, error: "Faltan parámetros." });

    const { data: user, error } = await supabase
      .from("usuarios")
      .select("codigo_verificacion, codigo_verificacion_expiry, email_verificado")
      .eq("slug", cleanSlug(slug))
      .maybeSingle();

    if (error) throw error;
    if (!user) return res.status(404).json({ success: false, error: "Usuario no encontrado." });
    if (user.email_verificado) return res.json({ success: true, ya_verificado: true });
    if (user.codigo_verificacion !== codigo.trim())
      return res.status(400).json({ success: false, error: "Código incorrecto." });
    if (new Date(user.codigo_verificacion_expiry) < new Date())
      return res.status(400).json({ success: false, error: "El código expiró. Pedí uno nuevo." });

    const { error: updError } = await supabase.from("usuarios").update({
      email_verificado:           true,
      codigo_verificacion:        null,
      codigo_verificacion_expiry: null,
    }).eq("slug", cleanSlug(slug));
    if (updError) throw updError;

    invalidateCache(slug);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ success: false, error: "No se pudo verificar el código." });
  }
});
// ══════════════════════════════════════════════════════════════
// NEGOCIO PÚBLICO
// GET /negocio/:slug
// ══════════════════════════════════════════════════════════════
app.get("/negocio/:slug", async (req, res) => {
  try {
    const slug = cleanSlug(req.params.slug);
    if (!slug) return res.status(400).json({ success: false, error: "Slug inválido." });
 
const { data: user, error } = await supabase.from("usuarios")
  .select(
    "slug, business_name, horarios, excepciones, duracion_turno, capacidad_por_turno, " +
    "metodo_pago, porcentaje_sena, mp_access_token, activo, plan, estado_suscripcion, " +
    "fecha_vencimiento, tema, logo_url, acepta_transferencia, acepta_efectivo, datos_bancarios, telefono"
  )
  .eq("slug", slug)
  .maybeSingle();
 
    if (error) throw error;
    if (!user)              return res.status(404).json({ success: false, error: "Negocio no encontrado." });
    if (!isActivo(user.activo)) return res.status(404).json({ success: false, error: "Negocio no disponible." });
 
    const diasRestantes  = user.fecha_vencimiento ? diasHastaVencer(user.fecha_vencimiento) : null;
    const estaSuspendido = user.estado_suscripcion === "suspendido" || (diasRestantes !== null && diasRestantes <= 0);
 
    if (estaSuspendido) {
      if (user.estado_suscripcion !== "suspendido") {
        supabase.from("usuarios").update({ estado_suscripcion: "suspendido" }).eq("slug", slug).then(() => {});
      }
      return res.json({ success: true, suspendido: true, negocio: { slug: user.slug, business_name: user.business_name } });
    }
 
    const esPremium               = user.plan === "premium";
    const mpDisponible            = !!user.mp_access_token && ["sena", "total"].includes(user.metodo_pago);
    const transferenciaDisponible = esPremium && !!user.acepta_transferencia;
    const efectivoDisponible      = esPremium && !!user.acepta_efectivo;
 
    const metodos_pago_disponibles = [
      ...(mpDisponible            ? ["mercadopago"]  : []),
      ...(transferenciaDisponible ? ["transferencia"] : []),
      ...(efectivoDisponible      ? ["efectivo"]      : []),
    ];
 
    res.json({
      success: true,
      negocio: {
        slug:                user.slug,
        business_name:       user.business_name,
        telefono:            user.telefono || null,
        horarios:            user.horarios            || {},
        excepciones:         user.excepciones         || [],
        duracion_turno:      user.duracion_turno      || 30,
        capacidad_por_turno: user.capacidad_por_turno || 1,
        metodo_pago:         user.metodo_pago         || "none",
        porcentaje_sena:     user.porcentaje_sena     || 30,
        tiene_mp:            !!user.mp_access_token,
        plan:                user.plan                || "gratis",
        tema:                user.tema                || null,
        logo_url:            user.logo_url            || null,
        metodos_pago_disponibles,
        datos_bancarios:     transferenciaDisponible ? (user.datos_bancarios || {}) : null,
      },
    });
  } catch (e) {
    console.error("Error en /negocio:", e.message);
    res.status(500).json({ success: false, error: "Error al obtener el negocio." });
  }
});

const UUID_REGEX =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

async function resolverExtras(slugClean, servicioId, extraIdsRaw) {
  const ids = Array.isArray(extraIdsRaw)
    ? [...new Set(extraIdsRaw.filter((id) => typeof id === "string" && UUID_REGEX.test(id)))]
    : [];
  if (ids.length === 0) return { extras: [], montoExtras: 0 };

  const { data: extrasDB } = await supabase.from("extras")
    .select("id, nombre, precio").eq("slug", slugClean).eq("activo", true).in("id", ids);
  if (!extrasDB?.length) return { extras: [], montoExtras: 0 };

  let permitidos = new Set(extrasDB.map((e) => e.id));
  if (servicioId) {
    const { data: vinculos } = await supabase.from("servicio_extras")
      .select("extra_id").eq("servicio_id", servicioId).in("extra_id", [...permitidos]);
    permitidos = new Set((vinculos || []).map((v) => v.extra_id));
  }

  const extras = extrasDB
    .filter((e) => permitidos.has(e.id))
    .map((e) => ({ id: e.id, nombre: e.nombre, precio: Number(e.precio) || 0 }));
  const montoExtras = extras.reduce((acc, e) => acc + e.precio, 0);
  return { extras, montoExtras };
}

app.get("/extras/:servicio_id", async (req, res) => {
  try {
    const { servicio_id } = req.params;
    if (!servicio_id || !UUID_REGEX.test(servicio_id)) {
      return res.status(400).json({ success: false, error: "servicio_id inválido." });
    }
 
    const { data: vinculos, error } = await supabase
      .from("servicio_extras")
      .select("extra_id, extras!inner(id, nombre, descripcion, precio, imagen_url, activo, orden)")
      .eq("servicio_id", servicio_id)
      .eq("extras.activo", true);
 
    if (error) throw error;
 
    const extras = (vinculos || [])
      .map((v) => v.extras)
      .filter(Boolean)
      .sort((a, b) => (a.orden || 0) - (b.orden || 0))
      .map(({ id, nombre, descripcion, precio, imagen_url }) => ({
        id, nombre, descripcion, precio, imagen_url,
      }));
 
    res.json({ success: true, extras });
  } catch (e) {
    console.error("Error en /extras/:servicio_id:", e.message);
    res.status(500).json({ success: false, error: "Error al obtener los extras." });
  }
});

// ══════════════════════════════════════════════════════════════
// SLOTS DISPONIBLES
// GET /slots-disponibles/:slug
// ══════════════════════════════════════════════════════════════
app.get("/slots-disponibles/:slug", async (req, res) => {
  try {
    const slug = cleanSlug(req.params.slug);
    const { fecha, servicio_id } = req.query;
    if (!slug || !fecha) return res.status(400).json({ success: false, error: "Faltan slug o fecha." });
    if (!/^\d{4}-\d{2}-\d{2}$/.test(fecha)) return res.status(400).json({ success: false, error: "Formato de fecha inválido." });

    const { data: user, error: userError } = await supabase.from("usuarios")
      .select("horarios, duracion_turno, capacidad_por_turno, excepciones, activo, estado_suscripcion, fecha_vencimiento")
      .eq("slug", slug).maybeSingle();
    if (userError) throw userError;
    if (!user || !isActivo(user.activo)) return res.status(404).json({ success: false, error: "Negocio no encontrado." });

    const diasRestantes  = user.fecha_vencimiento ? diasHastaVencer(user.fecha_vencimiento) : null;
    const estaSuspendido = user.estado_suscripcion === "suspendido" || (diasRestantes !== null && diasRestantes <= 0);
    if (estaSuspendido) return res.json({ success: true, slots: [], suspendido: true, puede_anotarse_espera: false });

    let duracionSolicitada = user.duracion_turno      || 30;
    let capacidad          = user.capacidad_por_turno || 1;

    if (servicio_id) {
      const { data: srv } = await supabase.from("servicios").select("duracion, capacidad")
        .eq("id", servicio_id).eq("slug", slug).maybeSingle();
      if (srv) { duracionSolicitada = srv.duracion || duracionSolicitada; capacidad = srv.capacidad || capacidad; }
    }

const intervalosDia = obtenerIntervalosDia(user.horarios, user.excepciones, fecha);
if (!intervalosDia) return res.json({ success: true, slots: [], puede_anotarse_espera: false });

const toMin   = (t) => { if (!t) return null; const [h, m] = t.split(":").map(Number); return h * 60 + m; };
const fromMin = (m) => `${Math.floor(m / 60).toString().padStart(2, "0")}:${(m % 60).toString().padStart(2, "0")}`;

const slotsGenerados = [];
intervalosDia.forEach(([ini, fin]) => {
  let cursor = ini;
  while (cursor + duracionSolicitada <= fin) {
    slotsGenerados.push(cursor);
    cursor += duracionSolicitada;
  }
});

    const { data: turnosDia } = await supabase.from("turnos").select("hora, estado, servicio_id")
      .eq("slug", slug).eq("fecha", fecha).in("estado", ["confirmado", "pendiente"]);
    const { data: todosServicios } = await supabase.from("servicios").select("id, duracion").eq("slug", slug);

    const duracionPorServicio = {};
    (todosServicios || []).forEach((s) => { duracionPorServicio[s.id] = s.duracion; });

    const rangosOcupados = (turnosDia || []).map((t) => {
      const inicioTurno = toMin(t.hora.slice(0, 5));
      const durTurno    = (t.servicio_id && duracionPorServicio[t.servicio_id]) ? duracionPorServicio[t.servicio_id] : (user.duracion_turno || 30);
      return { inicio: inicioTurno, fin: inicioTurno + durTurno };
    });

    const ahoraArg      = new Date(new Date().toLocaleString("en-US", { timeZone: "America/Argentina/Buenos_Aires" }));
    const hoyISO         = ahoraArg.toISOString().split("T")[0];
    const esHoy           = fecha === hoyISO;
    const minutosAhora    = esHoy ? (ahoraArg.getHours() * 60 + ahoraArg.getMinutes()) : null;

    const slots = slotsGenerados
      .filter((slotInicio) => !esHoy || slotInicio > minutosAhora)
      .map((slotInicio) => {
        const slotFin   = slotInicio + duracionSolicitada;
        const solapados = rangosOcupados.filter(({ inicio, fin }) => slotInicio < fin && slotFin > inicio).length;
        const disponibles = Math.max(0, capacidad - solapados);
        return { hora: fromMin(slotInicio), disponibles, lleno: disponibles <= 0 };
      });

    const puedeAnotarseEspera = slots.every((s) => s.lleno);

    res.json({ success: true, slots, puede_anotarse_espera: puedeAnotarseEspera });
  } catch (e) {
    console.error("Error en /slots-disponibles:", e.message);
    res.status(500).json({ success: false, error: "Error al obtener los turnos disponibles." });
  }
});

// ══════════════════════════════════════════════════════════════
// SERVICIOS — PÚBLICOS
// GET /servicios/:slug
// ══════════════════════════════════════════════════════════════
app.get("/servicios/:slug", async (req, res) => {
  try {
    const slug = cleanSlug(req.params.slug);
    if (!slug) return res.status(400).json({ success: false, error: "Slug inválido." });
    const { data, error } = await supabase.from("servicios")
      .select("id, nombre, descripcion, duracion, precio, capacidad")
      .eq("slug", slug).eq("activo", "true")
      .order("orden", { ascending: true }).order("created_at", { ascending: true });
    if (error) throw error;
    res.json({ success: true, servicios: data || [] });
  } catch (e) {
    res.status(500).json({ success: false, error: "Error al obtener los servicios." });
  }
});

// ══════════════════════════════════════════════════════════════
// SERVICIOS — ADMIN — UPLOAD IMAGEN
// POST /admin/servicios/upload-imagen
// FIX-SEC: multer ya filtra por mimetype (ver TIPOS_IMAGEN_PERMITIDOS).
// Se agrega manejo del error de multer para devolver 400 en vez de 500.
// ══════════════════════════════════════════════════════════════
app.post("/admin/servicios/upload-imagen", requireAuth, (req, res, next) => {
  upload.single("imagen")(req, res, (err) => {
    if (err) return res.status(400).json({ success: false, error: err.message });
    next();
  });
}, async (req, res) => {
  try {
    const slug = cleanSlug(req.body.slug || req.auth.slug);
    if (!req.file) return res.status(400).json({ success: false, error: "No se recibió imagen." });

    const ext      = req.file.mimetype === "image/png" ? "png" : req.file.mimetype === "image/webp" ? "webp" : "jpg";
    const fileName = `${slug}/${Date.now()}.${ext}`;

    const { error } = await supabase.storage
      .from("servicios")
      .upload(fileName, req.file.buffer, { contentType: req.file.mimetype, upsert: true });

    if (error) throw error;

    const { data } = supabase.storage.from("servicios").getPublicUrl(fileName);
    res.json({ success: true, url: data.publicUrl });
  } catch (e) {
    console.error("Error upload imagen:", e.message);
    res.status(500).json({ success: false, error: "No se pudo subir la imagen." });
  }
});

const PRECIO_MINIMO_EXTRA = 100; // ajustá si querés otro piso
 
function validarExtraBody({ nombre, precio }) {
  if (!nombre || !nombre.trim() || nombre.trim().length > 80) return "Nombre inválido.";
  const p = Number(precio);
  if (!Number.isFinite(p) || p < PRECIO_MINIMO_EXTRA) return `El precio mínimo es $${PRECIO_MINIMO_EXTRA}.`;
  return null;
}

// ══════════════════════════════════════════════════════════════
// SERVICIOS — ADMIN — CRUD
// FIX: estas rutas faltaban por completo. Es la causa del
// "Ruta no encontrada" al crear/editar/listar servicios desde el
// panel — ServiciosManager.tsx llama a GET/POST/PUT/DELETE
// /admin/servicios(/:id) y ninguna de esas rutas existía, así que
// caían en el handler 404 genérico. Los servicios viejos no se
// borraron de la base: el panel simplemente no podía traerlos
// porque GET /admin/servicios/:slug no existía.
// ══════════════════════════════════════════════════════════════

const PRECIO_MINIMO_SERVICIO = 2500; // mismo piso que usa el form en ServiciosManager.tsx

function validarServicioBody({ nombre, precio }) {
  if (!nombre || !nombre.trim() || nombre.trim().length > 80) return "Nombre inválido.";
  const p = Number(precio);
  if (!Number.isFinite(p) || p < PRECIO_MINIMO_SERVICIO) return `El precio mínimo es $${PRECIO_MINIMO_SERVICIO}.`;
  return null;
}

// GET /admin/servicios/:slug — todos los servicios del negocio (activos e inactivos)
app.get("/admin/servicios/:slug", requireAuth, async (req, res) => {
  try {
    const slug = cleanSlug(req.params.slug);
    const { data, error } = await supabase.from("servicios")
      .select("id, nombre, descripcion, duracion, precio, capacidad, activo, orden")
      .eq("slug", slug)
      .order("orden", { ascending: true }).order("created_at", { ascending: true });
    if (error) throw error;

    // FIX: mismo criterio que "usuarios.activo" — se guarda como texto
    // ("true"/"false"), no boolean, así que se normaliza con isActivo()
    // antes de devolverlo (el frontend espera un boolean real).
    const servicios = (data || []).map((s) => ({ ...s, activo: isActivo(s.activo) }));
    res.json({ success: true, servicios });
  } catch (e) {
    console.error("Error en GET /admin/servicios:", e.message);
    res.status(500).json({ success: false, error: "Error al obtener los servicios." });
  }
});

// POST /admin/servicios — crear servicio
app.post("/admin/servicios", requireAuth, async (req, res) => {
  try {
    const { slug, nombre, descripcion, duracion, precio, capacidad, orden } = req.body;
    const slugClean = cleanSlug(slug || req.auth.slug);

    const errorValidacion = validarServicioBody({ nombre, precio });
    if (errorValidacion) return res.status(400).json({ success: false, error: errorValidacion });
    if (descripcion !== undefined && descripcion !== null && String(descripcion).length > 1000) {
      return res.status(400).json({ success: false, error: "La descripción es demasiado larga." });
    }

    const dur = parseInt(duracion);
    const cap = parseInt(capacidad);

    const { data, error } = await supabase.from("servicios").insert([{
      slug: slugClean,
      nombre: nombre.trim(),
      descripcion: descripcion?.trim() || null,
      duracion: Number.isFinite(dur) && dur > 0 ? dur : 30,
      precio: Number(precio),
      capacidad: Number.isFinite(cap) && cap > 0 ? cap : 1,
      orden: parseInt(orden) || 0,
      activo: "true",
    }]).select().single();

    if (error) throw error;
    invalidateCache(slugClean);
    res.status(201).json({ success: true, servicio: { ...data, activo: isActivo(data.activo) } });
  } catch (e) {
    console.error("Error creando servicio:", e.message);
    res.status(500).json({ success: false, error: "No se pudo crear el servicio." });
  }
});

// PUT /admin/servicios/:id — editar servicio (también usada para el toggle activo/inactivo)
app.put("/admin/servicios/:id", requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const slugClean = cleanSlug(req.body.slug || req.auth.slug);
    const { nombre, descripcion, duracion, precio, capacidad, orden, activo } = req.body;

    const update = {};

    if (nombre !== undefined) {
      if (!nombre || !nombre.trim() || nombre.trim().length > 80) {
        return res.status(400).json({ success: false, error: "Nombre inválido." });
      }
      update.nombre = nombre.trim();
    }
    if (precio !== undefined) {
      const p = Number(precio);
      if (!Number.isFinite(p) || p < PRECIO_MINIMO_SERVICIO) {
        return res.status(400).json({ success: false, error: `El precio mínimo es $${PRECIO_MINIMO_SERVICIO}.` });
      }
      update.precio = p;
    }
    if (descripcion !== undefined) {
      if (descripcion !== null && String(descripcion).length > 1000) {
        return res.status(400).json({ success: false, error: "La descripción es demasiado larga." });
      }
      update.descripcion = descripcion?.trim() || null;
    }
    if (duracion !== undefined) {
      const d = parseInt(duracion);
      if (!Number.isFinite(d) || d <= 0 || d > 1440) {
        return res.status(400).json({ success: false, error: "Duración inválida." });
      }
      update.duracion = d;
    }
    if (capacidad !== undefined) {
      const c = parseInt(capacidad);
      if (!Number.isFinite(c) || c <= 0 || c > 500) {
        return res.status(400).json({ success: false, error: "Capacidad inválida." });
      }
      update.capacidad = c;
    }
    if (orden !== undefined) update.orden = parseInt(orden) || 0;
    if (activo !== undefined) update.activo = (activo === true || activo === "true") ? "true" : "false";

    if (Object.keys(update).length === 0) {
      return res.status(400).json({ success: false, error: "No hay campos para actualizar." });
    }

    const { data, error } = await supabase.from("servicios")
      .update(update).eq("id", id).eq("slug", slugClean)
      .select().single();

    if (error) throw error;
    if (!data) return res.status(404).json({ success: false, error: "Servicio no encontrado." });

    invalidateCache(slugClean);
    res.json({ success: true, servicio: { ...data, activo: isActivo(data.activo) } });
  } catch (e) {
    console.error("Error actualizando servicio:", e.message);
    res.status(500).json({ success: false, error: "No se pudo actualizar el servicio." });
  }
});

// DELETE /admin/servicios/:id
// NOTA: si algún turno viejo quedó referenciando este servicio_id
// (columna turnos.servicio_id) y esa FK no tiene ON DELETE SET NULL
// o CASCADE, el DELETE puede fallar. Si te pasa eso, contame y
// lo resolvemos (lo más simple: ON DELETE SET NULL en esa FK, ya
// que turnos guarda servicio_nombre/precio_cobrado como snapshot
// y no depende de que el servicio siga existiendo).
app.delete("/admin/servicios/:id", requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const slugClean = cleanSlug(req.body?.slug || req.query?.slug || req.auth.slug);
    const { error } = await supabase.from("servicios").delete().eq("id", id).eq("slug", slugClean);
    if (error) throw error;
    invalidateCache(slugClean);
    res.json({ success: true });
  } catch (e) {
    console.error("Error eliminando servicio:", e.message);
    res.status(500).json({ success: false, error: "No se pudo eliminar el servicio." });
  }
});

// ══════════════════════════════════════════════════════════════
// EXTRAS — ADMIN — CRUD
// ══════════════════════════════════════════════════════════════
 
// GET /admin/extras/:slug  — todos los productos del negocio
app.get("/admin/extras/:slug", requireAuth, async (req, res) => {
  try {
    const slug = cleanSlug(req.params.slug);
    const { data, error } = await supabase.from("extras")
      .select("*").eq("slug", slug)
      .order("orden", { ascending: true }).order("created_at", { ascending: true });
    if (error) throw error;
    res.json({ success: true, extras: data || [] });
  } catch (e) {
    res.status(500).json({ success: false, error: "Error al obtener los productos." });
  }
});
 
// POST /admin/extras  — crear producto
app.post("/admin/extras", requireAuth, async (req, res) => {
  try {
    const { slug, nombre, descripcion, precio, imagen_url, orden } = req.body;
    const slugClean = cleanSlug(slug || req.auth.slug);
 
    const errorValidacion = validarExtraBody({ nombre, precio });
    if (errorValidacion) return res.status(400).json({ success: false, error: errorValidacion });
    if (descripcion !== undefined && descripcion !== null && String(descripcion).length > 300) {
      return res.status(400).json({ success: false, error: "La descripción es demasiado larga." });
    }
 
    const { data, error } = await supabase.from("extras").insert([{
      slug: slugClean,
      nombre: nombre.trim(),
      descripcion: descripcion?.trim() || null,
      precio: Number(precio),
      imagen_url: imagen_url || null,
      orden: parseInt(orden) || 0,
      activo: true,
    }]).select().single();
 
    if (error) throw error;
    res.status(201).json({ success: true, extra: data });
  } catch (e) {
    console.error("Error creando extra:", e.message);
    res.status(500).json({ success: false, error: "No se pudo crear el producto." });
  }
});
 
// PUT /admin/extras/:id  — editar producto
app.put("/admin/extras/:id", requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const slugClean = cleanSlug(req.body.slug || req.auth.slug);
    const { nombre, descripcion, precio, imagen_url, activo, orden } = req.body;
 
    const update = {};
    if (nombre !== undefined || precio !== undefined) {
      // si se toca nombre o precio, revalidar el par completo contra
      // lo que llegó (evita mandar un precio viejo inválido a mitad de edición)
      const errorValidacion = validarExtraBody({
        nombre: nombre !== undefined ? nombre : "placeholder",
        precio: precio !== undefined ? precio : PRECIO_MINIMO_EXTRA,
      });
      if (nombre !== undefined && (!nombre || !nombre.trim() || nombre.trim().length > 80)) {
        return res.status(400).json({ success: false, error: "Nombre inválido." });
      }
      if (precio !== undefined) {
        const p = Number(precio);
        if (!Number.isFinite(p) || p < PRECIO_MINIMO_EXTRA) {
          return res.status(400).json({ success: false, error: `El precio mínimo es $${PRECIO_MINIMO_EXTRA}.` });
        }
        update.precio = p;
      }
      if (nombre !== undefined) update.nombre = nombre.trim();
    }
    if (descripcion !== undefined) {
      if (descripcion !== null && String(descripcion).length > 300) {
        return res.status(400).json({ success: false, error: "La descripción es demasiado larga." });
      }
      update.descripcion = descripcion?.trim() || null;
    }
    if (imagen_url !== undefined) update.imagen_url = imagen_url || null;
    if (activo !== undefined) update.activo = activo === true || activo === "true";
    if (orden !== undefined) update.orden = parseInt(orden) || 0;
 
    if (Object.keys(update).length === 0) {
      return res.status(400).json({ success: false, error: "No hay campos para actualizar." });
    }
 
    const { data, error } = await supabase.from("extras")
      .update(update).eq("id", id).eq("slug", slugClean)
      .select().single();
 
    if (error) throw error;
    if (!data) return res.status(404).json({ success: false, error: "Producto no encontrado." });
    res.json({ success: true, extra: data });
  } catch (e) {
    res.status(500).json({ success: false, error: "No se pudo actualizar el producto." });
  }
});
 
// DELETE /admin/extras/:id
// (servicio_extras tiene ON DELETE CASCADE, así que se desvincula solo)
app.delete("/admin/extras/:id", requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const slugClean = cleanSlug(req.body?.slug || req.query?.slug || req.auth.slug);
    const { error } = await supabase.from("extras").delete().eq("id", id).eq("slug", slugClean);
    if (error) throw error;
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ success: false, error: "No se pudo eliminar el producto." });
  }
});
 
// POST /admin/extras/upload-imagen  — mismo patrón que servicios,
// bucket "extras" en vez de "servicios"
app.post("/admin/extras/upload-imagen", requireAuth, (req, res, next) => {
  upload.single("imagen")(req, res, (err) => {
    if (err) return res.status(400).json({ success: false, error: err.message });
    next();
  });
}, async (req, res) => {
  try {
    const slug = cleanSlug(req.body.slug || req.auth.slug);
    if (!req.file) return res.status(400).json({ success: false, error: "No se recibió imagen." });
 
    const ext = req.file.mimetype === "image/png" ? "png" : req.file.mimetype === "image/webp" ? "webp" : "jpg";
    const fileName = `${slug}/${Date.now()}.${ext}`;
 
    const { error } = await supabase.storage
      .from("extras")
      .upload(fileName, req.file.buffer, { contentType: req.file.mimetype, upsert: true });
 
    if (error) throw error;
 
    const { data } = supabase.storage.from("extras").getPublicUrl(fileName);
    res.json({ success: true, url: data.publicUrl });
  } catch (e) {
    console.error("Error upload imagen extra:", e.message);
    res.status(500).json({ success: false, error: "No se pudo subir la imagen." });
  }
});
 
// ══════════════════════════════════════════════════════════════
// EXTRAS — VINCULACIÓN CON SERVICIOS (tabla servicio_extras)
// ══════════════════════════════════════════════════════════════
 
// GET /admin/servicios/:id/extras-disponibles
// Todos los productos del negocio + cuál está vinculado a ESTE
// servicio en particular. Pensado para pintar de una sola vez el
// selector de "Productos relacionados" en el panel.
app.get("/admin/servicios/:id/extras-disponibles", requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const slugClean = cleanSlug(req.query.slug || req.auth.slug);
 
    const [{ data: extras, error: e1 }, { data: vinculos, error: e2 }] = await Promise.all([
      supabase.from("extras").select("*").eq("slug", slugClean)
        .order("orden", { ascending: true }).order("created_at", { ascending: true }),
      supabase.from("servicio_extras").select("extra_id").eq("servicio_id", id),
    ]);
    if (e1) throw e1;
    if (e2) throw e2;
 
    const vinculadosSet = new Set((vinculos || []).map((v) => v.extra_id));
    const resultado = (extras || []).map((e) => ({ ...e, vinculado: vinculadosSet.has(e.id) }));
 
    res.json({ success: true, extras: resultado });
  } catch (e) {
    res.status(500).json({ success: false, error: "Error al obtener los productos." });
  }
});
 
// POST /admin/servicios/:id/extras  — vincular un producto existente
app.post("/admin/servicios/:id/extras", requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { extra_id } = req.body;
    const slugClean = cleanSlug(req.body.slug || req.auth.slug);
    if (!extra_id) return res.status(400).json({ success: false, error: "Falta extra_id." });
 
    // Validar que el servicio y el extra sean del mismo negocio
    // (evita que alguien vincule un extra de otro negocio a mano).
    const [{ data: servicio }, { data: extra }] = await Promise.all([
      supabase.from("servicios").select("id").eq("id", id).eq("slug", slugClean).maybeSingle(),
      supabase.from("extras").select("id").eq("id", extra_id).eq("slug", slugClean).maybeSingle(),
    ]);
    if (!servicio) return res.status(404).json({ success: false, error: "Servicio no encontrado." });
    if (!extra) return res.status(404).json({ success: false, error: "Producto no encontrado." });
 
    const { error } = await supabase.from("servicio_extras")
      .upsert([{ servicio_id: id, extra_id }], { onConflict: "servicio_id,extra_id" });
    if (error) throw error;
 
    res.status(201).json({ success: true });
  } catch (e) {
    res.status(500).json({ success: false, error: "No se pudo vincular el producto." });
  }
});
 
// DELETE /admin/servicios/:id/extras/:extra_id  — desvincular
app.delete("/admin/servicios/:id/extras/:extra_id", requireAuth, async (req, res) => {
  try {
    const { id, extra_id } = req.params;
    const { error } = await supabase.from("servicio_extras")
      .delete().eq("servicio_id", id).eq("extra_id", extra_id);
    if (error) throw error;
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ success: false, error: "No se pudo desvincular el producto." });
  }
});

// ══════════════════════════════════════════════════════════════
// LISTA DE ESPERA
// ══════════════════════════════════════════════════════════════
app.post("/turnos/lista-espera", limiterBooking, async (req, res) => {
  try {
    const { slug, fecha, servicio_id, nombre, telefono, email, canal_aviso } = req.body;
    const slugClean = cleanSlug(slug || "");
    const canal = ["email", "whatsapp", "ambos"].includes(canal_aviso) ? canal_aviso : null;

    if (!slugClean || !fecha || !nombre || !canal) {
      return res.status(400).json({ success: false, error: "Faltan datos requeridos." });
    }
    if (!/^\d{4}-\d{2}-\d{2}$/.test(fecha)) return res.status(400).json({ success: false, error: "Formato de fecha inválido." });
    if (nombre.trim().length < 2 || nombre.trim().length > 80) return res.status(400).json({ success: false, error: "Nombre inválido." });
    if ((canal === "email" || canal === "ambos") && !email)
      return res.status(400).json({ success: false, error: "Falta el email." });
    if ((canal === "whatsapp" || canal === "ambos") && !telefono)
      return res.status(400).json({ success: false, error: "Falta el teléfono." });
    if (email && !validateEmail(email))
      return res.status(400).json({ success: false, error: "Email inválido." });

    const phoneClean = telefono ? cleanPhone(telefono.toString()) : null;
    if (phoneClean && !validatePhone(phoneClean))
      return res.status(400).json({ success: false, error: "Teléfono inválido." });

    const { data: user, error: userError } = await supabase.from("usuarios")
      .select("horarios, excepciones, activo, estado_suscripcion, fecha_vencimiento")
      .eq("slug", slugClean).maybeSingle();
    if (userError) throw userError;
    if (!user || !isActivo(user.activo)) return res.status(404).json({ success: false, error: "Negocio no encontrado." });

    const diasRestantes  = user.fecha_vencimiento ? diasHastaVencer(user.fecha_vencimiento) : null;
    const estaSuspendido = user.estado_suscripcion === "suspendido" || (diasRestantes !== null && diasRestantes <= 0);
    if (estaSuspendido) return res.status(403).json({ success: false, error: "Este servicio está pausado temporalmente." });

    const intervalosDia = obtenerIntervalosDia(user.horarios, user.excepciones, fecha);
    if (!intervalosDia) return res.status(400).json({ success: false, error: "Ese día no es un día laboral." });

    const emailClean = email?.trim().toLowerCase() || null;

    const { data: entrada, error } = await supabase.from("lista_espera").insert([{
      slug: slugClean, fecha, servicio_id: servicio_id || null,
      nombre: nombre.trim(), telefono: phoneClean, email: emailClean,
      canal_aviso: canal, estado: "pendiente",
    }]).select().single();
    if (error) {
      if (error.code === "23505") return res.status(409).json({ success: false, error: "Ya estás anotado en la lista de espera para ese día." });
      throw error;
    }

    res.status(201).json({ success: true, id: entrada.id, message: "Te anotamos en la lista de espera. Te avisamos si se libera un turno." });
  } catch (e) {
    console.error("Error en /turnos/lista-espera:", e.message);
    res.status(500).json({ success: false, error: "No se pudo anotar en la lista de espera." });
  }
});

app.get("/admin/lista-espera/:slug", requireAuth, async (req, res) => {
  try {
    const slug = cleanSlug(req.params.slug);
    const { data, error } = await supabase.from("lista_espera")
      .select("*").eq("slug", slug).eq("estado", "pendiente")
      .order("fecha", { ascending: true }).order("created_at", { ascending: true });
    if (error) throw error;
    res.json({ success: true, lista_espera: data || [] });
  } catch (e) {
    res.status(500).json({ success: false, error: "Error al obtener la lista de espera." });
  }
});

app.delete("/admin/lista-espera/:id", requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const slugClean = cleanSlug(req.body?.slug || req.query?.slug || req.auth.slug);
    const { error } = await supabase.from("lista_espera").delete().eq("id", id).eq("slug", slugClean);
    if (error) throw error;
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ success: false, error: "No se pudo eliminar." });
  }
});

// Cron diario: borra solicitudes de días que ya pasaron sin liberarse
app.get("/cron/limpiar-lista-espera", requireAdminKey, async (req, res) => {
  try {
    const hoyISO = new Date(new Date().toLocaleString("en-US", { timeZone: "America/Argentina/Buenos_Aires" })).toISOString().split("T")[0];
    const { data, error } = await supabase.from("lista_espera")
      .delete().lt("fecha", hoyISO).eq("estado", "pendiente").select("id");
    if (error) throw error;
    res.json({ success: true, borrados: data?.length || 0 });
  } catch (e) {
    res.status(500).json({ success: false, error: "Error al limpiar la lista de espera." });
  }
});

// ══════════════════════════════════════════════════════════════
// TURNOS — RESERVA PÚBLICA (sin pago)
// POST /turnos/reservar
// ══════════════════════════════════════════════════════════════
app.post("/turnos/reservar", limiterBooking, async (req, res) => {
  try {
    const { name, phone, email, fecha, hora, slug, servicio_id, apellido, extra_ids } = req.body;
    const slugClean = cleanSlug(slug || "");

    if (!name || !phone || !fecha || !hora || !slugClean) {
      return res.status(400).json({ success: false, error: "Faltan datos requeridos." });
    }
    if (!/^\d{4}-\d{2}-\d{2}$/.test(fecha)) return res.status(400).json({ success: false, error: "Formato de fecha inválido." });
    if (name.trim().length < 2 || name.trim().length > 80) return res.status(400).json({ success: false, error: "Nombre inválido." });
    const phoneClean = cleanPhone(phone.toString());
    if (!validatePhone(phoneClean)) return res.status(400).json({ success: false, error: "Teléfono inválido (7-15 dígitos)." });
    if (email && !validateEmail(email)) return res.status(400).json({ success: false, error: "Email inválido." });

    const { data: user, error: userError } = await supabase.from("usuarios")
      .select("*").eq("slug", slugClean).maybeSingle();
    if (userError) throw userError;
    if (!user)              return res.status(404).json({ success: false, error: "Negocio no encontrado." });
    if (!isActivo(user.activo)) return res.status(404).json({ success: false, error: "Negocio no disponible." });

    const diasRestantes  = user.fecha_vencimiento ? diasHastaVencer(user.fecha_vencimiento) : null;
    const estaSuspendido = user.estado_suscripcion === "suspendido" || (diasRestantes !== null && diasRestantes <= 0);
    if (estaSuspendido) return res.status(403).json({ success: false, error: "Este servicio está pausado temporalmente." });

    const esPlanGratis = user.plan === "gratis";
    const tieneMP      = !!user.mp_access_token;
    const requierePago = tieneMP && (user.metodo_pago === "sena" || user.metodo_pago === "total");

    if (esPlanGratis && !tieneMP) {
      return res.status(403).json({
        success: false,
        error:   "free_no_payment_method",
        message: "Este negocio aún no configuró un método de pago.",
      });
    }

    if (requierePago) return res.status(403).json({ success: false, error: "Este turno requiere pago previo." });

    const hoy = new Date().toISOString().split("T")[0];
    const emailClean = email?.trim().toLowerCase();
    const [porTelefono, porEmail] = await Promise.all([
      supabase.from("turnos").select("id")
        .eq("slug", slugClean).gte("fecha", hoy).neq("estado", "cancelado").eq("telefono", phoneClean),
      emailClean
        ? supabase.from("turnos").select("id")
            .eq("slug", slugClean).gte("fecha", hoy).neq("estado", "cancelado").eq("email", emailClean)
        : Promise.resolve({ data: [] }),
    ]);
    const turnosExistentes = [...(porTelefono.data || []), ...(porEmail.data || [])];
    if (turnosExistentes.length > 0) return res.status(400).json({ success: false, error: "Ya tenés un turno agendado activo." });

let capacidad      = user.capacidad_por_turno || 1;
let servicioNombre = null;
let precioCobrado  = 0;

if (servicio_id) {
  const { data: srv } = await supabase.from("servicios")
    .select("nombre, capacidad, precio")
    .eq("id", servicio_id).maybeSingle();
  if (srv) {
    servicioNombre = srv.nombre;
    capacidad      = srv.capacidad || capacidad;
    precioCobrado  = Number(srv.precio || 0);
  }
}

const { extras: extrasResueltos, montoExtras } = await resolverExtras(slugClean, servicio_id || null, extra_ids);

    const { count } = await supabase.from("turnos").select("id", { count: "exact" })
      .eq("slug", slugClean).eq("fecha", fecha).eq("hora", hora).neq("estado", "cancelado");
    if (count >= capacidad) return res.status(400).json({ success: false, error: "Este turno ya está lleno." });

const { data: turno, error: turnoError } = await supabase.from("turnos").insert([{
  slug:            slugClean,
  nombre:          name.trim(),
  telefono:        phoneClean,
  apellido:        apellido?.trim().slice(0, 80) || null,
  email:           emailClean || null,
  fecha,
  hora,
  servicio_id:     servicio_id || null,
  servicio_nombre: servicioNombre,
  precio_cobrado:  precioCobrado + montoExtras,   // ← total real
  extras:          extrasResueltos,               // ← nuevo
  monto_extras:    montoExtras,                   // ← nuevo
  monto_pagado:    0,
  estado:          "confirmado",
  metodo_pago:     "none",
  pago_estado:     "sin_pago",
}]).select().single();
    if (turnoError) throw turnoError;
    
    enviarMailTurno({
      adminEmail:    user.email,
      emailCliente:  emailClean || "",
      nombreCliente: name.trim(),
      fechaHora:     `${fecha} ${hora}`,
      slug:          slugClean,
      servicio:      servicioNombre || "",
      precioTotal:   precioCobrado,
      montoOnline:   0,
      metodoPago:    user.metodo_pago || "none",
    });

    enviarWhatsappTurno({
      telefono:      phoneClean,
      nombreCliente: name.trim(),
      businessName:  user.business_name,
      fechaHora:     `${fecha} ${hora}`,
      servicio:      servicioNombre || "",
    });

    crearNotificacion({
      slug: slugClean,
      tipo: "turno_nuevo",
      titulo: "Nuevo turno reservado",
      mensaje: `${name.trim()} reservó ${servicioNombre ? servicioNombre + " " : ""}para el ${fecha} a las ${hora}hs.`,
      data: { turno_id: turno.id, fecha, hora },
    });

    invalidateCache(slugClean);

    const comprobanteUrl = `${SUCCESS_URL}?slug=${slugClean}&turno_id=${turno.id}`;
    res.json({ success: true, turno_id: turno.id, comprobante_url: comprobanteUrl, message: "Turno creado con éxito." });
  } catch (e) {
    console.error("Error en /turnos/reservar:", e.message);
    res.status(500).json({ success: false, error: "No se pudo crear el turno." });
  }
});

// ══════════════════════════════════════════════════════════════
// TURNOS — RESERVA MANUAL (transferencia / efectivo, solo premium)
// POST /turnos/reservar-manual
// Siempre queda estado = "pendiente" hasta que el vendedor la
// apruebe o rechace desde el panel.
// ══════════════════════════════════════════════════════════════
app.post("/turnos/reservar-manual", limiterBooking, (req, res, next) => {
  upload.single("comprobante")(req, res, (err) => {
    if (err) return res.status(400).json({ success: false, error: err.message });
    next();
  });
}, async (req, res) => {
  try {
    const { name, apellido, phone, email, fecha, hora, slug, servicio_id, metodo_pago } = req.body;
    let extraIds = [];
    try { extraIds = JSON.parse(req.body.extra_ids || "[]"); } catch { extraIds = []; }
    const slugClean = cleanSlug(slug || "");

    if (!name || !phone || !fecha || !hora || !slugClean || !metodo_pago) {
      return res.status(400).json({ success: false, error: "Faltan datos requeridos." });
    }
    if (!["transferencia", "efectivo"].includes(metodo_pago)) {
      return res.status(400).json({ success: false, error: "Método de pago inválido." });
    }
    if (!/^\d{4}-\d{2}-\d{2}$/.test(fecha)) return res.status(400).json({ success: false, error: "Formato de fecha inválido." });
    if (name.trim().length < 2 || name.trim().length > 80) return res.status(400).json({ success: false, error: "Nombre inválido." });

    const phoneClean = cleanPhone(phone.toString());
    if (!validatePhone(phoneClean)) return res.status(400).json({ success: false, error: "Teléfono inválido (7-15 dígitos)." });
    if (email && !validateEmail(email)) return res.status(400).json({ success: false, error: "Email inválido." });

    if (metodo_pago === "transferencia" && !req.file) {
      return res.status(400).json({ success: false, error: "Adjuntá el comprobante de la transferencia." });
    }

    const { data: user, error: userError } = await supabase.from("usuarios").select("*").eq("slug", slugClean).maybeSingle();
    if (userError) throw userError;
    if (!user) return res.status(404).json({ success: false, error: "Negocio no encontrado." });
    if (!isActivo(user.activo)) return res.status(404).json({ success: false, error: "Negocio no disponible." });

    const diasRestantes  = user.fecha_vencimiento ? diasHastaVencer(user.fecha_vencimiento) : null;
    const estaSuspendido = user.estado_suscripcion === "suspendido" || (diasRestantes !== null && diasRestantes <= 0);
    if (estaSuspendido) return res.status(403).json({ success: false, error: "Este servicio está pausado temporalmente." });

    // FIX-SEC: transferencia/efectivo son exclusivos de premium. Se
    // revalida acá (no solo confiar en lo que muestra el front) por
    // si el negocio bajó de plan después de haber tenido esto activo.
    if (user.plan !== "premium") {
      return res.status(403).json({ success: false, error: "Este negocio no ofrece este método de pago." });
    }
    if (metodo_pago === "transferencia" && !user.acepta_transferencia) {
      return res.status(403).json({ success: false, error: "Este negocio no acepta pagos por transferencia." });
    }
    if (metodo_pago === "efectivo" && !user.acepta_efectivo) {
      return res.status(403).json({ success: false, error: "Este negocio no acepta pagos en efectivo." });
    }

    const emailClean = email?.trim().toLowerCase();

    let capacidad      = user.capacidad_por_turno || 1;
    let servicioNombre = null;
    let precioCobrado  = 0;
    if (servicio_id) {
      const { data: srv } = await supabase.from("servicios").select("nombre, capacidad, precio").eq("id", servicio_id).maybeSingle();
      if (srv) { servicioNombre = srv.nombre; capacidad = srv.capacidad || capacidad; precioCobrado = Number(srv.precio || 0); }
    }
    const { extras: extrasResueltos, montoExtras } = await resolverExtras(slugClean, servicio_id || null, extraIds);

    const { count } = await supabase.from("turnos").select("id", { count: "exact" })
      .eq("slug", slugClean).eq("fecha", fecha).eq("hora", hora).neq("estado", "cancelado");
    if (count >= capacidad) return res.status(400).json({ success: false, error: "Este turno ya está lleno." });

    let comprobantePath = null;
    if (metodo_pago === "transferencia") {
      const ext = req.file.mimetype === "image/png" ? "png" : req.file.mimetype === "image/webp" ? "webp" : "jpg";
      comprobantePath = `${slugClean}/${Date.now()}-${crypto.randomUUID()}.${ext}`;
      const { error: upErr } = await supabase.storage.from("comprobantes")
        .upload(comprobantePath, req.file.buffer, { contentType: req.file.mimetype, upsert: false });
      if (upErr) throw upErr;
    }

    const { data: turno, error: turnoError } = await supabase.from("turnos").insert([{
      slug: slugClean, nombre: name.trim(), apellido: apellido?.trim().slice(0, 80) || null,
      telefono: phoneClean, email: emailClean || null, fecha, hora,
      servicio_id: servicio_id || null, servicio_nombre: servicioNombre,
      precio_cobrado: precioCobrado + montoExtras,   // ← total real
      extras: extrasResueltos,                        // ← nuevo
      monto_extras: montoExtras,                      // ← nuevo
      monto_pagado: 0,
      estado: "pendiente", metodo_pago,
      pago_estado: metodo_pago === "transferencia" ? "pendiente" : "sin_pago",
      comprobante_path: comprobantePath,
    }]).select().single();
    if (turnoError) throw turnoError;

    // Mail al vendedor avisando que hay un turno para aprobar.
    if (APPS_SCRIPT_URL) {
      fetch(APPS_SCRIPT_URL, {
        method: "POST", headers: { "Content-Type": "text/plain" },
        body: JSON.stringify({
          action:      "turnoPendienteAprobacion",
          adminEmail:  user.email,
          nombreCliente: name.trim(),
          fechaHora:   `${fecha} ${hora}`,
          slug:        slugClean,
          servicio:    servicioNombre || "",
          metodoPago:  metodo_pago,
          precioTotal: precioCobrado,
          panelUrl:    `${PANEL_URL}?u=${slugClean}`,
        }),
      }).catch((e) => console.error("Error mail turno pendiente:", e.message));
    }

    crearNotificacion({
      slug: slugClean,
      tipo: "turno_pendiente",
      titulo: `Nuevo turno pendiente (${metodo_pago})`,
      mensaje: `${name.trim()} reservó ${servicioNombre ? servicioNombre + " " : ""}para el ${fecha} a las ${hora}hs y espera tu aprobación (${metodo_pago}).`,
      data: { turno_id: turno.id, fecha, hora, metodo_pago },
    });

    invalidateCache(slugClean);

    res.status(201).json({
      success: true,
      turno_id: turno.id,
      estado: "pendiente",
      message: "Tu reserva quedó pendiente de aprobación. Te avisamos apenas el negocio la confirme.",
    });
  } catch (e) {
    console.error("Error en /turnos/reservar-manual:", e.message);
    res.status(500).json({ success: false, error: "No se pudo crear la reserva." });
  }
});

// ══════════════════════════════════════════════════════════════
// TURNOS — COMPROBANTE PÚBLICO
// GET /turnos/publico/:id
// ══════════════════════════════════════════════════════════════
app.get("/turnos/publico/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const slug   = cleanSlug(req.query.slug || "");
    if (!id || !slug) return res.status(400).json({ success: false, error: "Faltan parámetros." });

    const { data: turno, error } = await supabase.from("turnos")
      .select("id, nombre, apellido, email, telefono, fecha, hora, servicio_nombre, precio_cobrado, monto_pagado, porcentaje_sena, metodo_pago, pago_estado, estado, extras, monto_extras")
      .eq("id", id).eq("slug", slug).maybeSingle();

    if (error) throw error;
    if (!turno) return res.status(404).json({ success: false, error: "Turno no encontrado." });

    res.json({ success: true, turno });
  } catch (e) {
    res.status(500).json({ success: false, error: "Error al obtener el turno." });
  }
});

// ══════════════════════════════════════════════════════════════
// TURNOS — BUSCAR POR PAYMENT_ID
// GET /turnos/by-payment
// ══════════════════════════════════════════════════════════════
app.get("/turnos/by-payment", async (req, res) => {
  try {
    const { payment_id, slug } = req.query;
    if (!payment_id || !slug) return res.status(400).json({ success: false, error: "Faltan parámetros." });

    const { data: turno, error } = await supabase.from("turnos")
      .select("id, nombre, apellido, email, telefono, fecha, hora, servicio_nombre, precio_cobrado, monto_pagado, porcentaje_sena, metodo_pago, pago_estado, estado, fecha_pago, extras, monto_extras")
      .eq("payment_id", String(payment_id)).eq("slug", cleanSlug(slug)).maybeSingle();

    if (error) throw error;
    if (!turno) return res.status(404).json({ success: false, error: "Turno no encontrado." });

    res.json({ success: true, turno });
  } catch (e) {
    res.status(500).json({ success: false, error: "Error al obtener el turno." });
  }
});

// ══════════════════════════════════════════════════════════════
// TURNOS — PENDIENTES DE APROBACIÓN (transferencia / efectivo)
// GET /admin/turnos-pendientes/:slug
// ══════════════════════════════════════════════════════════════
app.get("/admin/turnos-pendientes/:slug", requireAuth, async (req, res) => {
  try {
    const slug = cleanSlug(req.params.slug);
    const { data, error } = await supabase.from("turnos")
      .select("id, nombre, apellido, telefono, email, fecha, hora, servicio_nombre, precio_cobrado, metodo_pago, pago_estado, comprobante_path, created_at")
      .eq("slug", slug).eq("estado", "pendiente").in("metodo_pago", ["transferencia", "efectivo"])
      .order("fecha", { ascending: true }).order("hora", { ascending: true });
    if (error) throw error;

    const turnos = (data || []).map((t) => ({ ...t, tiene_comprobante: !!t.comprobante_path }));
    res.json({ success: true, turnos_pendientes: turnos });
  } catch (e) {
    res.status(500).json({ success: false, error: "Error al obtener los turnos pendientes." });
  }
});

// Signed URL de corta duración — el comprobante NUNCA se sirve como
// URL pública porque puede tener CBU/alias/nombre del titular.
// GET /admin/turnos/:id/comprobante
app.get("/admin/turnos/:id/comprobante", requireAuth, async (req, res) => {
  try {
    const slugClean = cleanSlug(req.query.slug || req.auth.slug);
    const { data: turno, error } = await supabase.from("turnos")
      .select("comprobante_path").eq("id", req.params.id).eq("slug", slugClean).maybeSingle();
    if (error) throw error;
    if (!turno?.comprobante_path) return res.status(404).json({ success: false, error: "No hay comprobante para este turno." });

    const { data: signed, error: signError } = await supabase.storage
      .from("comprobantes").createSignedUrl(turno.comprobante_path, 60 * 10); // 10 minutos
    if (signError) throw signError;

    res.json({ success: true, url: signed.signedUrl });
  } catch (e) {
    res.status(500).json({ success: false, error: "No se pudo obtener el comprobante." });
  }
});

// ══════════════════════════════════════════════════════════════
// TURNOS — ACTUALIZAR ESTADO (admin)
// PUT /turnos/:id
// Incluye el efecto de "aprobar" un turno pendiente por
// transferencia/efectivo: pasa el pago a aprobado y avisa al
// cliente por mail + WhatsApp. Rechazar sigue el flujo normal:
// estado="cancelado", libera cupo y avisa a la lista de espera.
// ══════════════════════════════════════════════════════════════
app.put("/turnos/:id", requireAuth, async (req, res) => {
  try {
    const { id }    = req.params;
    const slugClean = cleanSlug(req.body?.slug || req.auth?.slug || "");
    const { estado, notas } = req.body;

    const ESTADOS_VALIDOS = ["confirmado", "pendiente", "cancelado", "completado", "no_asistio"];
    if (!estado || !ESTADOS_VALIDOS.includes(estado)) {
      return res.status(400).json({ success: false, error: `Estado inválido. Debe ser uno de: ${ESTADOS_VALIDOS.join(", ")}` });
    }
    if (notas !== undefined && notas !== null && String(notas).length > 1000) {
      return res.status(400).json({ success: false, error: "Las notas son demasiado largas." });
    }

    const { data: turnoExistente, error: fetchError } = await supabase
      .from("turnos")
      .select("id, slug, estado, fecha, hora, nombre, apellido, email, telefono, servicio_nombre, metodo_pago, pago_estado, precio_cobrado")
      .eq("id", id).eq("slug", slugClean).maybeSingle();

    if (fetchError) throw fetchError;
    if (!turnoExistente) return res.status(404).json({ success: false, error: "Turno no encontrado." });

    // Aprobación de un turno manual (transferencia/efectivo) pendiente
    const esAprobacionManual =
      estado === "confirmado" &&
      turnoExistente.estado === "pendiente" &&
      ["transferencia", "efectivo"].includes(turnoExistente.metodo_pago);

    const updateData = { estado };
    if (notas !== undefined) updateData.notas = notas;
if (esAprobacionManual) {
  updateData.pago_estado  = "aprobado";
  updateData.monto_pagado = turnoExistente.precio_cobrado || 0;
  updateData.fecha_pago   = new Date().toISOString();
}

    const { data: turnoActualizado, error: updateError } = await supabase
      .from("turnos").update(updateData).eq("id", id).eq("slug", slugClean).select().single();

    if (updateError) throw updateError;

    const ESTADOS_OCUPAN = ["confirmado", "pendiente"];
    const liberaCupo = ESTADOS_OCUPAN.includes(turnoExistente.estado) && !ESTADOS_OCUPAN.includes(estado);
    if (liberaCupo) {
      notificarListaEspera(slugClean, turnoExistente.fecha).catch((e) => console.error("Error notificando lista de espera:", e.message));
    }

    if (estado === "cancelado" && turnoExistente.estado !== "cancelado") {
      crearNotificacion({
        slug: slugClean,
        tipo: "turno_cancelado",
        titulo: "Turno cancelado",
        mensaje: `Se canceló el turno de ${turnoExistente.nombre || "un cliente"} del ${turnoExistente.fecha} a las ${turnoExistente.hora?.slice(0, 5) || ""}hs.`,
        data: { turno_id: id, fecha: turnoExistente.fecha },
      });
    }

    // Avisar al cliente que su turno (transferencia/efectivo) fue aprobado.
    if (esAprobacionManual) {
      if (turnoExistente.email && APPS_SCRIPT_URL) {
        fetch(APPS_SCRIPT_URL, {
          method: "POST", headers: { "Content-Type": "text/plain" },
          body: JSON.stringify({
            action:        "newAppointmentEmailCliente",
            nombreCliente: turnoExistente.nombre,
            fechaHora:     `${turnoExistente.fecha} ${turnoExistente.hora.slice(0, 5)}`,
            emailCliente:  turnoExistente.email,
            slug:          slugClean,
            servicio:      turnoExistente.servicio_nombre || "",
            precioTotal:   turnoExistente.precio_cobrado || 0,
            montoOnline:   turnoExistente.metodo_pago === "transferencia" ? (turnoExistente.precio_cobrado || 0) : 0,
            metodoPago:    turnoExistente.metodo_pago,
          }),
        }).catch((e) => console.error("Error mail aprobación turno:", e.message));
      }

      const { data: negocio } = await supabase.from("usuarios").select("business_name").eq("slug", slugClean).maybeSingle();
      enviarWhatsappTurno({
        telefono:      turnoExistente.telefono,
        nombreCliente: turnoExistente.nombre,
        businessName:  negocio?.business_name,
        fechaHora:     `${turnoExistente.fecha} ${turnoExistente.hora.slice(0, 5)}`,
        servicio:      turnoExistente.servicio_nombre || "",
      });
    }

    invalidateCache(slugClean);
    console.log(`✅ Turno ${id} → ${estado} (${slugClean})`);
    res.json({ success: true, turno: turnoActualizado });
  } catch (e) {
    console.error("Error en PUT /turnos/:id:", e.message);
    res.status(500).json({ success: false, error: "No se pudo actualizar el turno." });
  }
});

// ══════════════════════════════════════════════════════════════
// AGENDA — Próximos 30 días
// GET /agenda/:slug
// ══════════════════════════════════════════════════════════════
app.get("/agenda/:slug", requireAuth, async (req, res) => {
  try {
    const slug     = cleanSlug(req.params.slug);
    const ahoraArg = new Date(new Date().toLocaleString("en-US", { timeZone: "America/Argentina/Buenos_Aires" }));
    const hoyISO   = ahoraArg.toISOString().split("T")[0];
    const hasta    = new Date(ahoraArg); hasta.setDate(hasta.getDate() + 30);
    const hastaISO = hasta.toISOString().split("T")[0];

    const { data: turnos, error } = await supabase.from("turnos").select("*")
      .eq("slug", slug).gte("fecha", hoyISO).lte("fecha", hastaISO).neq("estado", "cancelado")
      .order("fecha", { ascending: true }).order("hora", { ascending: true });
    if (error) throw error;

    const porFecha = {};
    (turnos || []).forEach((t) => {
      if (!porFecha[t.fecha]) porFecha[t.fecha] = [];
porFecha[t.fecha].push({
    id:             t.id,
    nombre:         t.nombre,
    apellido:       t.apellido || null,
    hora:           t.hora.slice(0, 5),
    servicio:       t.servicio_nombre || null,
    precio_cobrado: t.precio_cobrado  || 0,
    monto_pagado:   t.monto_pagado    || 0,
    pago_estado:    t.pago_estado     || "sin_pago",
    metodo_pago:    t.metodo_pago     || "none",
    estado:         t.estado,
    email:          t.email,
    telefono:       t.telefono,
    notas:          t.notas || null,
    extras:         t.extras       || [],   // ← nuevo
    monto_extras:   t.monto_extras || 0,     // ← nuevo
});
    });

    const dias = Object.keys(porFecha).sort().map((fecha) => ({ fecha, esHoy: fecha === hoyISO, turnos: porFecha[fecha] }));
    res.json({ success: true, hoy: hoyISO, dias });
  } catch (e) {
    res.status(500).json({ success: false, error: "Error al obtener la agenda." });
  }
});

// ══════════════════════════════════════════════════════════════
// SETTINGS
// ══════════════════════════════════════════════════════════════
app.get("/settings/:slug", requireAuth, async (req, res) => {
  try {
    const slug = cleanSlug(req.params.slug);
    const { data: user, error } = await supabase.from("usuarios")
      .select(
        "slug, business_name, nombre_persona, apellido, email, telefono, " +
        "plan, duracion_turno, capacidad_por_turno, metodo_pago, porcentaje_sena, " +
        "horarios, excepciones, mp_access_token, " +
        "estado_suscripcion, fecha_vencimiento, activo, " +
        "acepta_transferencia, acepta_efectivo, datos_bancarios"
      )
      .eq("slug", slug).maybeSingle();

    if (error) throw error;
    if (!user) return res.status(404).json({ success: false, error: "Negocio no encontrado." });

    const diasRestantes = user.fecha_vencimiento ? diasHastaVencer(user.fecha_vencimiento) : null;

    res.json({
      success: true,
      settings: {
        slug:                user.slug,
        business_name:       user.business_name,
        nombre_persona:      user.nombre_persona,
        apellido:            user.apellido,
        email:               user.email,
        telefono:            user.telefono,
        plan:                user.plan || "gratis",
        duracion_turno:      user.duracion_turno,
        capacidad_por_turno: user.capacidad_por_turno,
        metodo_pago:         user.metodo_pago,
        porcentaje_sena:     user.porcentaje_sena,
        horarios:            user.horarios    || {},
        excepciones:         user.excepciones || [],
        activo:              isActivo(user.activo),
        estado_suscripcion:  user.estado_suscripcion,
        fecha_vencimiento:   user.fecha_vencimiento,
        mp_status:           user.mp_access_token ? "Conectado" : "Desconectado",
        dias_restantes:      diasRestantes,
        alerta_vencimiento:  diasRestantes !== null && diasRestantes <= 5 && diasRestantes > 0,
        acepta_transferencia: !!user.acepta_transferencia,
        acepta_efectivo:      !!user.acepta_efectivo,
        datos_bancarios:      user.datos_bancarios || {},
      },
    });
  } catch (e) {
    res.status(500).json({ success: false, error: "Error al obtener la configuración." });
  }
});

// FIX-SEC: se valida la forma de horarios/excepciones antes de guardar
// (ver validarHorarios / validarExcepciones), y se acotan largos de
// texto libre (business_name, nombre_persona, apellido).
app.put("/settings/:slug", requireAuth, async (req, res) => {
  try {
    const slug = cleanSlug(req.params.slug);
    if (!slug) return res.status(400).json({ success: false, error: "Slug inválido." });

    const ALLOWED_FIELDS = [
      "business_name", "nombre_persona", "apellido", "telefono",
      "duracion_turno", "capacidad_por_turno",
      "metodo_pago", "porcentaje_sena",
      "horarios", "excepciones",
      "acepta_transferencia", "acepta_efectivo", "datos_bancarios",
    ];

    const update = {};
    ALLOWED_FIELDS.forEach((field) => {
      if (req.body[field] !== undefined) update[field] = req.body[field];
    });

    if (update.duracion_turno !== undefined) {
      const d = parseInt(update.duracion_turno);
      if (!Number.isFinite(d) || d <= 0 || d > 1440) return res.status(400).json({ success: false, error: "Duración de turno inválida." });
      update.duracion_turno = d;
    }
    if (update.capacidad_por_turno !== undefined) {
      const c = parseInt(update.capacidad_por_turno);
      if (!Number.isFinite(c) || c <= 0 || c > 500) return res.status(400).json({ success: false, error: "Capacidad inválida." });
      update.capacidad_por_turno = c;
    }
    if (update.porcentaje_sena !== undefined) {
      const p = parseInt(update.porcentaje_sena);
      if (!Number.isFinite(p) || p < 1 || p > 100) return res.status(400).json({ success: false, error: "Porcentaje de seña inválido." });
      update.porcentaje_sena = p;
    }
    if (update.metodo_pago !== undefined && !["none", "sena", "total"].includes(update.metodo_pago)) {
      return res.status(400).json({ success: false, error: "Método de pago inválido." });
    }
    if (update.telefono !== undefined) {
      const tel = cleanPhone(update.telefono);
      if (!validatePhone(tel)) return res.status(400).json({ success: false, error: "Teléfono inválido." });
      update.telefono = tel;
    }
    if (update.business_name !== undefined) {
      if (update.business_name.trim().length < 2 || update.business_name.trim().length > 80) return res.status(400).json({ success: false, error: "Nombre de negocio inválido." });
      update.business_name = update.business_name.trim();
    }
    if (update.nombre_persona !== undefined) {
      if (update.nombre_persona.trim().length < 2 || update.nombre_persona.trim().length > 80) return res.status(400).json({ success: false, error: "Nombre inválido." });
      update.nombre_persona = update.nombre_persona.trim();
    }
    if (update.apellido !== undefined) update.apellido = String(update.apellido).trim().slice(0, 80);

    if (update.excepciones !== undefined && !Array.isArray(update.excepciones)) {
      update.excepciones = Object.entries(update.excepciones).map(([fecha, exc]) => ({
        fecha, type: exc.type ?? "block",
        ...(exc.slots ? { slots: exc.slots } : {}),
      }));
    }

    if (update.horarios !== undefined && !validarHorarios(update.horarios)) {
      return res.status(400).json({ success: false, error: "Formato de horarios inválido." });
    }
    if (update.excepciones !== undefined && !validarExcepciones(update.excepciones)) {
      return res.status(400).json({ success: false, error: "Formato de excepciones inválido." });
    }

    if (update.acepta_transferencia !== undefined || update.acepta_efectivo !== undefined || update.datos_bancarios !== undefined) {
      const { data: negocioActual } = await supabase.from("usuarios").select("plan").eq("slug", slug).maybeSingle();
      if (!negocioActual) return res.status(404).json({ success: false, error: "Negocio no encontrado." });
      if (negocioActual.plan !== "premium") {
        return res.status(403).json({ success: false, error: "Transferencia y efectivo son exclusivos del plan Premium." });
      }
    }
    if (update.acepta_transferencia !== undefined) {
      update.acepta_transferencia = update.acepta_transferencia === true || update.acepta_transferencia === "true";
    }
    if (update.acepta_efectivo !== undefined) {
      update.acepta_efectivo = update.acepta_efectivo === true || update.acepta_efectivo === "true";
    }
    if (update.datos_bancarios !== undefined && !validarDatosBancarios(update.datos_bancarios)) {
      return res.status(400).json({ success: false, error: "Datos bancarios inválidos (revisá CBU/alias)." });
    }

    if (Object.keys(update).length === 0) {
      return res.status(400).json({ success: false, error: "No hay campos válidos para actualizar." });
    }

    const { error } = await supabase.from("usuarios").update(update).eq("slug", slug);
    if (error) throw error;
    invalidateCache(slug);
    res.json({ success: true, updated: Object.keys(update) });
  } catch (e) {
    res.status(500).json({ success: false, error: "No se pudo actualizar la configuración." });
  }
});

app.get("/reprogramar/info/:turno_id", async (req, res) => {
  try {
    const { turno_id } = req.params;
    const slug  = cleanSlug(req.query.slug || "");
    const token = req.query.token || "";
 
    if (!turno_id || !UUID_REGEX.test(turno_id) || !slug || !token) {
      return res.status(400).json({ success: false, error: "Parámetros inválidos." });
    }
 
    const { data: turno, error } = await supabase.from("turnos")
      .select("id, slug, nombre, fecha, hora, servicio_nombre, estado, gestion_token")
      .eq("id", turno_id).eq("slug", slug).maybeSingle();
    if (error) throw error;
    if (!turno) return res.status(404).json({ success: false, error: "Turno no encontrado." });
    if (!tokenDeGestionValido(token, turno.gestion_token)) {
      return res.status(403).json({ success: false, error: "Link inválido." });
    }
 
    const { data: pendiente } = await supabase.from("reprogramaciones")
      .select("id, fecha_propuesta, hora_propuesta")
      .eq("turno_id", turno_id).eq("estado", "pendiente").maybeSingle();
 
    const hoy = new Date().toISOString().split("T")[0];
    const puedeReprogramar =
      ["confirmado", "pendiente"].includes(turno.estado) &&
      turno.fecha >= hoy &&
      !pendiente;
 
    res.json({
      success: true,
      turno: {
        nombre:    turno.nombre,
        fecha:     turno.fecha,
        hora:      turno.hora.slice(0, 5),
        servicio:  turno.servicio_nombre,
        estado:    turno.estado,
      },
      puede_reprogramar: puedeReprogramar,
      solicitud_pendiente: pendiente
        ? { fecha_propuesta: pendiente.fecha_propuesta, hora_propuesta: pendiente.hora_propuesta }
        : null,
    });
  } catch (e) {
    console.error("Error en /reprogramar/info:", e.message);
    res.status(500).json({ success: false, error: "Error al obtener el turno." });
  }
});
 
// POST /reprogramar/solicitar
// Body: { turno_id, slug, token, fecha_nueva, hora_nueva }
app.post("/reprogramar/solicitar", limiterBooking, async (req, res) => {
  try {
    const { turno_id, slug, token, fecha_nueva, hora_nueva } = req.body;
    const slugClean = cleanSlug(slug || "");
 
    if (!turno_id || !UUID_REGEX.test(turno_id) || !slugClean || !token || !fecha_nueva || !hora_nueva) {
      return res.status(400).json({ success: false, error: "Faltan datos requeridos." });
    }
    if (!/^\d{4}-\d{2}-\d{2}$/.test(fecha_nueva)) {
      return res.status(400).json({ success: false, error: "Formato de fecha inválido." });
    }
    if (!/^([01]\d|2[0-3]):([0-5]\d)$/.test(hora_nueva)) {
      return res.status(400).json({ success: false, error: "Formato de hora inválido." });
    }
 
    const { data: turno, error: turnoError } = await supabase.from("turnos")
      .select("id, slug, fecha, hora, estado, servicio_id, gestion_token")
      .eq("id", turno_id).eq("slug", slugClean).maybeSingle();
    if (turnoError) throw turnoError;
    if (!turno) return res.status(404).json({ success: false, error: "Turno no encontrado." });
    if (!tokenDeGestionValido(token, turno.gestion_token)) {
      return res.status(403).json({ success: false, error: "Link inválido." });
    }
    if (!["confirmado", "pendiente"].includes(turno.estado)) {
      return res.status(400).json({ success: false, error: "Este turno ya no se puede reprogramar." });
    }
 
    const horaActualFmt = turno.hora.slice(0, 5);
    if (fecha_nueva === turno.fecha && hora_nueva === horaActualFmt) {
      return res.status(400).json({ success: false, error: "Elegí una fecha u horario distinto al actual." });
    }
 
    const { data: user, error: userError } = await supabase.from("usuarios")
      .select("horarios, excepciones, capacidad_por_turno, activo, estado_suscripcion, fecha_vencimiento, email, business_name")
      .eq("slug", slugClean).maybeSingle();
    if (userError) throw userError;
    if (!user || !isActivo(user.activo)) return res.status(404).json({ success: false, error: "Negocio no encontrado." });
 
    const diasRestantes  = user.fecha_vencimiento ? diasHastaVencer(user.fecha_vencimiento) : null;
    const estaSuspendido = user.estado_suscripcion === "suspendido" || (diasRestantes !== null && diasRestantes <= 0);
    if (estaSuspendido) return res.status(403).json({ success: false, error: "Este servicio está pausado temporalmente." });
 
    if (!horaDentroDeIntervalos(user.horarios, user.excepciones, fecha_nueva, hora_nueva)) {
      return res.status(400).json({ success: false, error: "Ese día u horario no está disponible." });
    }
 
    // Chequeo de cupo "soft" (se vuelve a validar al aprobar, para
    // evitar condiciones de carrera entre que se pide y se aprueba).
    let capacidad = user.capacidad_por_turno || 1;
    if (turno.servicio_id) {
      const { data: srv } = await supabase.from("servicios").select("capacidad").eq("id", turno.servicio_id).maybeSingle();
      if (srv?.capacidad) capacidad = srv.capacidad;
    }
    const { count } = await supabase.from("turnos").select("id", { count: "exact" })
      .eq("slug", slugClean).eq("fecha", fecha_nueva).eq("hora", hora_nueva).neq("estado", "cancelado");
    if (count >= capacidad) {
      return res.status(400).json({ success: false, error: "Ese horario ya está lleno, elegí otro." });
    }
 
    const { data: solicitud, error: insertError } = await supabase.from("reprogramaciones").insert([{
      turno_id, slug: slugClean,
      fecha_actual: turno.fecha, hora_actual: horaActualFmt,
      fecha_propuesta: fecha_nueva, hora_propuesta: hora_nueva,
      estado: "pendiente",
    }]).select().single();
 
    if (insertError) {
      // Viola el índice único de "1 pendiente por turno"
      if (insertError.code === "23505") {
        return res.status(409).json({ success: false, error: "Ya tenés una solicitud de reprogramación pendiente para este turno." });
      }
      throw insertError;
    }
 
    if (APPS_SCRIPT_URL && user.email) {
      fetch(APPS_SCRIPT_URL, {
        method: "POST", headers: { "Content-Type": "text/plain" },
        body: JSON.stringify({
          action: "reprogramacionSolicitada",
          adminEmail: user.email,
          fechaActual: `${turno.fecha} ${horaActualFmt}`,
          fechaPropuesta: `${fecha_nueva} ${hora_nueva}`,
          slug: slugClean,
          panelUrl: `${PANEL_URL}?u=${slugClean}`,
        }),
      }).catch((e) => console.error("Error mail reprogramación solicitada:", e.message));
    }
 
    crearNotificacion({
      slug: slugClean,
      tipo: "reprogramacion_solicitada",
      titulo: "Solicitud de reprogramación",
      mensaje: `Un cliente pidió mover su turno del ${turno.fecha} ${horaActualFmt}hs al ${fecha_nueva} ${hora_nueva}hs. Revisalo en tu agenda.`,
      data: { turno_id, solicitud_id: solicitud.id, fecha_actual: turno.fecha, fecha_propuesta: fecha_nueva },
    });
 
    res.status(201).json({ success: true, message: "Solicitud enviada. Te avisamos cuando el negocio la responda." });
  } catch (e) {
    console.error("Error en /reprogramar/solicitar:", e.message);
    res.status(500).json({ success: false, error: "No se pudo enviar la solicitud." });
  }
});
 
 
// ────────────────────────────────────────────────────────────────
// BLOQUE 4 — Rutas de admin. Van junto a las otras rutas de
// /admin/turnos-pendientes (mismo bloque temático), antes de
// "TURNOS — ACTUALIZAR ESTADO (admin)".
// ────────────────────────────────────────────────────────────────
 
// GET /admin/reprogramaciones/:slug — pendientes, con datos del turno
app.get("/admin/reprogramaciones/:slug", requireAuth, async (req, res) => {
  try {
    const slug = cleanSlug(req.params.slug);
    const { data, error } = await supabase.from("reprogramaciones")
      .select("id, turno_id, fecha_actual, hora_actual, fecha_propuesta, hora_propuesta, created_at, turnos!inner(nombre, apellido, telefono, email, servicio_nombre)")
      .eq("slug", slug).eq("estado", "pendiente")
      .order("created_at", { ascending: true });
    if (error) throw error;
 
    const solicitudes = (data || []).map((s) => ({
      id: s.id, turno_id: s.turno_id,
      fecha_actual: s.fecha_actual, hora_actual: s.hora_actual,
      fecha_propuesta: s.fecha_propuesta, hora_propuesta: s.hora_propuesta,
      created_at: s.created_at,
      cliente: {
        nombre: s.turnos?.nombre, apellido: s.turnos?.apellido,
        telefono: s.turnos?.telefono, email: s.turnos?.email,
      },
      servicio: s.turnos?.servicio_nombre,
    }));
 
    res.json({ success: true, solicitudes });
  } catch (e) {
    console.error("Error en /admin/reprogramaciones:", e.message);
    res.status(500).json({ success: false, error: "Error al obtener las solicitudes." });
  }
});
 
// PUT /admin/reprogramaciones/:id — Body: { slug, accion: "aprobar" | "rechazar" }
app.put("/admin/reprogramaciones/:id", requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const slugClean = cleanSlug(req.body?.slug || req.auth?.slug || "");
    const { accion } = req.body;
 
    if (!["aprobar", "rechazar"].includes(accion)) {
      return res.status(400).json({ success: false, error: "Acción inválida." });
    }
 
    const { data: solicitud, error: fetchError } = await supabase.from("reprogramaciones")
      .select("*, turnos!inner(id, nombre, telefono, email, servicio_nombre, servicio_id)")
      .eq("id", id).eq("slug", slugClean).eq("estado", "pendiente").maybeSingle();
    if (fetchError) throw fetchError;
    if (!solicitud) return res.status(404).json({ success: false, error: "Solicitud no encontrada o ya resuelta." });
 
    const turno = solicitud.turnos;
 
    if (accion === "rechazar") {
      await supabase.from("reprogramaciones")
        .update({ estado: "rechazada", resuelto_at: new Date().toISOString() })
        .eq("id", id);
 
      if (APPS_SCRIPT_URL && turno.email) {
        fetch(APPS_SCRIPT_URL, {
          method: "POST", headers: { "Content-Type": "text/plain" },
          body: JSON.stringify({
            action: "reprogramacionRechazada",
            emailCliente: turno.email,
            nombreCliente: turno.nombre,
            fechaActual: `${solicitud.fecha_actual} ${solicitud.hora_actual}`,
            slug: slugClean,
          }),
        }).catch((e) => console.error("Error mail reprogramación rechazada:", e.message));
      }
      if (WHATSAPP_TEMPLATE_REPROG_RECHAZADA) {
        enviarWhatsapp(turno.telefono, WHATSAPP_TEMPLATE_REPROG_RECHAZADA, [
          { type: "body", parameters: [
            { type: "text", text: (turno.nombre || "Cliente").slice(0, 60) },
            { type: "text", text: `${solicitud.fecha_actual} ${solicitud.hora_actual}` },
          ]},
        ]).catch((e) => console.error("Error whatsapp reprogramación rechazada:", e.message));
      }
 
      return res.json({ success: true, estado: "rechazada" });
    }
 
    // accion === "aprobar" — re-chequeo de cupo (por si se llenó
    // entre que se pidió y se está aprobando ahora).
    let capacidad = 1;
    const { data: userCap } = await supabase.from("usuarios").select("capacidad_por_turno").eq("slug", slugClean).maybeSingle();
    capacidad = userCap?.capacidad_por_turno || 1;
    if (turno.servicio_id) {
      const { data: srv } = await supabase.from("servicios").select("capacidad").eq("id", turno.servicio_id).maybeSingle();
      if (srv?.capacidad) capacidad = srv.capacidad;
    }
    const { count } = await supabase.from("turnos").select("id", { count: "exact" })
      .eq("slug", slugClean).eq("fecha", solicitud.fecha_propuesta).eq("hora", solicitud.hora_propuesta)
      .neq("estado", "cancelado").neq("id", turno.id);
    if (count >= capacidad) {
      return res.status(409).json({
        success: false,
        error: "Ese horario ya no está disponible (se ocupó mientras tanto). Rechazá la solicitud o coordiná otra fecha con el cliente.",
      });
    }
 
    await supabase.from("turnos")
      .update({ fecha: solicitud.fecha_propuesta, hora: solicitud.hora_propuesta })
      .eq("id", turno.id);
 
    await supabase.from("reprogramaciones")
      .update({ estado: "aprobada", resuelto_at: new Date().toISOString() })
      .eq("id", id);
 
    // Se liberó el cupo original: avisar a la lista de espera de esa fecha.
    notificarListaEspera(slugClean, solicitud.fecha_actual)
      .catch((e) => console.error("Error notificando lista de espera:", e.message));
 
    if (APPS_SCRIPT_URL && turno.email) {
      fetch(APPS_SCRIPT_URL, {
        method: "POST", headers: { "Content-Type": "text/plain" },
        body: JSON.stringify({
          action: "reprogramacionAprobada",
          emailCliente: turno.email,
          nombreCliente: turno.nombre,
          fechaNueva: `${solicitud.fecha_propuesta} ${solicitud.hora_propuesta}`,
          servicio: turno.servicio_nombre || "",
          slug: slugClean,
        }),
      }).catch((e) => console.error("Error mail reprogramación aprobada:", e.message));
    }
    if (WHATSAPP_TEMPLATE_REPROG_APROBADA) {
      enviarWhatsapp(turno.telefono, WHATSAPP_TEMPLATE_REPROG_APROBADA, [
        { type: "body", parameters: [
          { type: "text", text: (turno.nombre || "Cliente").slice(0, 60) },
          { type: "text", text: `${solicitud.fecha_propuesta} ${solicitud.hora_propuesta}` },
        ]},
      ]).catch((e) => console.error("Error whatsapp reprogramación aprobada:", e.message));
    }
 
    crearNotificacion({
      slug: slugClean,
      tipo: "sistema",
      titulo: "Turno reprogramado",
      mensaje: `El turno de ${turno.nombre || "un cliente"} se movió al ${solicitud.fecha_propuesta} ${solicitud.hora_propuesta}hs.`,
      data: { turno_id: turno.id },
    });
 
    invalidateCache(slugClean);
    res.json({ success: true, estado: "aprobada" });
  } catch (e) {
    console.error("Error en PUT /admin/reprogramaciones/:id:", e.message);
    res.status(500).json({ success: false, error: "No se pudo procesar la solicitud." });
  }
});

// ══════════════════════════════════════════════════════════════
// TEMA — Guardar / Leer
// PUT/GET /admin/tema/:slug
// ══════════════════════════════════════════════════════════════
app.put("/admin/tema/:slug", requireAuth, async (req, res) => {
  try {
    const slug = cleanSlug(req.params.slug);
    const { primario, secundario, fondo, texto, acento, guardar_paleta, nombre_paleta } = req.body;

    const COLOR_KEYS = ["primario", "secundario", "fondo", "texto", "acento"];
    const temaActual = { primario, secundario, fondo, texto, acento };
    const temaFiltrado = {};
    COLOR_KEYS.forEach((key) => {
      const v = temaActual[key];
      if (v !== undefined && v !== null && v !== "") temaFiltrado[key] = v;
    });

    const { data: user, error: fetchError } = await supabase.from("usuarios")
      .select("tema, paletas_personalizadas").eq("slug", slug).maybeSingle();
    if (fetchError) throw fetchError;
    if (!user) return res.status(404).json({ success: false, error: "Negocio no encontrado." });

    const temaMerged = { ...(user.tema || {}), ...temaFiltrado };
    const update = { tema: temaMerged };

    if (guardar_paleta) {
      const COLORES_VALIDOS = /^#([0-9A-Fa-f]{3}|[0-9A-Fa-f]{6})$/;
      const camposOk = COLOR_KEYS.every((k) => COLORES_VALIDOS.test(temaMerged[k] || ""));
      if (!camposOk) {
        return res.status(400).json({ success: false, error: "Colores inválidos para guardar la paleta." });
      }
      const paletasActuales = Array.isArray(user.paletas_personalizadas) ? user.paletas_personalizadas : [];
      const nuevaPaleta = {
        id: crypto.randomUUID(),
        nombre: (nombre_paleta || "Mi paleta").trim().slice(0, 30),
        tema: temaMerged,
        created_at: new Date().toISOString(),
      };
      update.paletas_personalizadas = [...paletasActuales, nuevaPaleta].slice(-10);
    }

    if (Object.keys(temaFiltrado).length === 0 && !guardar_paleta) {
      return res.status(400).json({ success: false, error: "No hay valores de tema para guardar." });
    }

    const { error: updError } = await supabase.from("usuarios").update(update).eq("slug", slug);
    if (updError) throw updError;
    invalidateCache(slug);

    res.json({ success: true, tema: temaMerged, paletas_personalizadas: update.paletas_personalizadas || user.paletas_personalizadas || [] });
  } catch (e) {
    res.status(500).json({ success: false, error: "No se pudo guardar el tema." });
  }
});

app.get("/admin/tema/:slug", requireAuth, async (req, res) => {
  try {
    const slug = cleanSlug(req.params.slug);
    const { data: user, error } = await supabase.from("usuarios")
      .select("tema, logo_url, paletas_personalizadas").eq("slug", slug).maybeSingle();
    if (error) throw error;
    if (!user) return res.status(404).json({ success: false, error: "Negocio no encontrado." });

    res.json({
      success: true,
      tema: user.tema || {},
      logo_url: user.logo_url || null,
      paletas_personalizadas: user.paletas_personalizadas || [],
    });
  } catch (e) {
    res.status(500).json({ success: false, error: "Error al obtener el tema." });
  }
});

// ══════════════════════════════════════════════════════════════
// LOGO — Upload
// POST /admin/logo/:slug
// FIX-SEC: ya no se acepta SVG (era vector de XSS almacenado vía
// <script> embebido). multer filtra por mimetype centralizadamente
// (TIPOS_IMAGEN_PERMITIDOS). Se maneja el error de multer con 400.
// ══════════════════════════════════════════════════════════════
app.post("/admin/logo/:slug", requireAuth, (req, res, next) => {
  upload.single("logo")(req, res, (err) => {
    if (err) return res.status(400).json({ success: false, error: err.message });
    next();
  });
}, async (req, res) => {
  try {
    const slug = cleanSlug(req.params.slug);
    if (!req.file) return res.status(400).json({ success: false, error: "No se recibió imagen." });

    const ext      = req.file.mimetype === "image/png"  ? "png"
                   : req.file.mimetype === "image/webp" ? "webp"
                   : "jpg";
    const fileName = `${slug}/logo.${ext}`;

    await supabase.storage.from("logos").remove([
      `${slug}/logo.png`, `${slug}/logo.jpg`, `${slug}/logo.webp`,
    ]);

    const { error: uploadError } = await supabase.storage
      .from("logos")
      .upload(fileName, req.file.buffer, {
        contentType: req.file.mimetype,
        upsert: true,
      });

    if (uploadError) throw uploadError;

    const { data } = supabase.storage.from("logos").getPublicUrl(fileName);
    const logoUrl  = data.publicUrl + `?v=${Date.now()}`;

    const { error: updError } = await supabase.from("usuarios").update({ logo_url: logoUrl }).eq("slug", slug);
    if (updError) throw updError;
    invalidateCache(slug);

    res.json({ success: true, logo_url: logoUrl });
  } catch (e) {
    console.error("Error upload logo:", e.message);
    res.status(500).json({ success: false, error: "No se pudo subir el logo." });
  }
});

// DELETE /admin/logo/:slug
app.delete("/admin/logo/:slug", requireAuth, async (req, res) => {
  try {
    const slug = cleanSlug(req.params.slug);

    await supabase.storage.from("logos").remove([
      `${slug}/logo.png`, `${slug}/logo.jpg`, `${slug}/logo.webp`,
    ]);

    const { error: updError } = await supabase.from("usuarios").update({ logo_url: null }).eq("slug", slug);
    if (updError) throw updError;
    invalidateCache(slug);

    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ success: false, error: "No se pudo eliminar el logo." });
  }
});

// ══════════════════════════════════════════════════════════════
// EQUIPO — CRUD
// ══════════════════════════════════════════════════════════════

app.get("/admin/equipo/:slug", requireAuth, async (req, res) => {
  try {
    const slug = cleanSlug(req.params.slug);
    const { data, error } = await supabase.from("equipo")
      .select("*")
      .eq("slug", slug)
      .order("created_at", { ascending: true });
    if (error) throw error;
    res.json({ success: true, equipo: data || [] });
  } catch (e) {
    res.status(500).json({ success: false, error: "Error al obtener el equipo." });
  }
});

app.post("/admin/equipo", requireAuth, async (req, res) => {
  try {
    const { slug, nombre, apellido, color, rol } = req.body;
    const slugClean = cleanSlug(slug || req.auth.slug);

    if (!slugClean || !nombre) {
      return res.status(400).json({ success: false, error: "Faltan nombre y slug." });
    }
    if (nombre.trim().length < 1 || nombre.trim().length > 80) {
      return res.status(400).json({ success: false, error: "Nombre inválido." });
    }

    const COLORES_VALIDOS = /^#([0-9A-Fa-f]{3}|[0-9A-Fa-f]{6})$/;
    const colorFinal = color && COLORES_VALIDOS.test(color) ? color : "#6366F1";
    const ROLES_VALIDOS = ["colaborador", "admin"];
    const rolFinal = ROLES_VALIDOS.includes(rol) ? rol : "colaborador";

    const { data, error } = await supabase.from("equipo").insert([{
      slug:     slugClean,
      nombre:   nombre.trim(),
      apellido: apellido?.trim().slice(0, 80) || null,
      color:    colorFinal,
      rol:      rolFinal,
      activo:   true,
    }]).select().single();

    if (error) throw error;
    res.status(201).json({ success: true, miembro: data });
  } catch (e) {
    res.status(500).json({ success: false, error: "No se pudo crear el miembro del equipo." });
  }
});

app.put("/admin/equipo/:id", requireAuth, async (req, res) => {
  try {
    const { id }    = req.params;
    const slugClean = cleanSlug(req.body.slug || req.auth.slug);
    const { nombre, apellido, color, rol, activo } = req.body;

    const update = {};
    if (nombre !== undefined) {
      if (nombre.trim().length < 1 || nombre.trim().length > 80) return res.status(400).json({ success: false, error: "Nombre inválido." });
      update.nombre = nombre.trim();
    }
    if (apellido !== undefined) update.apellido = apellido.trim().slice(0, 80);
    if (color !== undefined) {
      const COLORES_VALIDOS = /^#([0-9A-Fa-f]{3}|[0-9A-Fa-f]{6})$/;
      if (!COLORES_VALIDOS.test(color)) return res.status(400).json({ success: false, error: "Color inválido." });
      update.color = color;
    }
    if (rol !== undefined) {
      if (!["colaborador", "admin"].includes(rol)) return res.status(400).json({ success: false, error: "Rol inválido." });
      update.rol = rol;
    }
    if (activo !== undefined) update.activo = activo === true || activo === "true";

    const { data, error } = await supabase.from("equipo")
      .update(update)
      .eq("id", id)
      .eq("slug", slugClean)
      .select().single();

    if (error) throw error;
    res.json({ success: true, miembro: data });
  } catch (e) {
    res.status(500).json({ success: false, error: "No se pudo actualizar." });
  }
});

app.delete("/admin/equipo/:id", requireAuth, async (req, res) => {
  try {
    const { id }    = req.params;
    const slugClean = cleanSlug(req.body?.slug || req.query?.slug || req.auth.slug);

    const { error } = await supabase.from("equipo")
      .delete()
      .eq("id", id)
      .eq("slug", slugClean);

    if (error) throw error;
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ success: false, error: "No se pudo eliminar." });
  }
});

// ══════════════════════════════════════════════════════════════
// ADMIN STATS
// GET /admin-stats/:slug
// ══════════════════════════════════════════════════════════════
app.get("/admin-stats/:slug", requireAuth, async (req, res) => {
  try {
    const slug = cleanSlug(req.params.slug);
    if (!slug) return res.status(400).json({ success: false, error: "Slug inválido." });

    const now = Date.now();
    if (globalCache[slug] && now - globalCache[slug].timestamp < CACHE_DURATION) {
      return res.json(globalCache[slug].data);
    }

    const { data: user, error: userError } = await supabase.from("usuarios")
      .select("id, slug, business_name, nombre_persona, apellido, email, activo, plan, metodo_pago, porcentaje_sena, duracion_turno, capacidad_por_turno, horarios, excepciones, mp_access_token, estado_suscripcion, fecha_vencimiento")
      .eq("slug", slug).maybeSingle();
    if (userError) throw userError;
    if (!user) return res.status(404).json({ success: false, error: "Negocio no encontrado." });

    const ahoraArg   = new Date(new Date().toLocaleString("en-US", { timeZone: "America/Argentina/Buenos_Aires" }));
    const anioActual = ahoraArg.getFullYear();
    const mesActual  = ahoraArg.getMonth() + 1;
    const diaHoyNum  = ahoraArg.getDate();
    const hoyISO     = `${anioActual}-${String(mesActual).padStart(2, "0")}-${String(diaHoyNum).padStart(2, "0")}`;
    const inicioMes  = `${anioActual}-${String(mesActual).padStart(2, "0")}-01`;

    const [{ data: turnosMes }, { data: serviciosNegocio }] = await Promise.all([
      supabase.from("turnos").select("*")
        .eq("slug", slug).gte("fecha", inicioMes).neq("estado", "cancelado")
        .order("fecha", { ascending: true }).order("hora", { ascending: true }),
      supabase.from("servicios").select("id, duracion")
        .eq("slug", slug).eq("activo", "true"),
    ]);

    const turnosData          = turnosMes || [];
    const duracionPorServicio = Object.fromEntries(
      (serviciosNegocio || []).map((s) => [s.id, s.duracion])
    );

    const turnosHoy      = turnosData.filter((t) => t.fecha === hoyISO).length;
    const turnosMesTotal = turnosData.length;

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
      apellido:       t.apellido || null,
      telefono:       t.telefono,
      email:          t.email,
      fecha:          t.fecha,
      hora:           t.hora.slice(0, 5),
      servicio:       t.servicio_nombre,
      precio_cobrado: t.precio_cobrado || 0,
      monto_pagado:   t.monto_pagado   || 0,
      pago_estado:    t.pago_estado    || "sin_pago",
      metodo_pago:    t.metodo_pago    || "none",
      estado:         t.estado,
      notas:          t.notas || null,
      duracion:       (t.servicio_id && duracionPorServicio[t.servicio_id])
                        ? duracionPorServicio[t.servicio_id]
                        : (user.duracion_turno || 30),
    })).reverse();

const turnosHoyDetalle = turnosData
    .filter((t) => t.fecha === hoyISO)
    .sort((a, b) => a.hora.localeCompare(b.hora))
    .map((t) => ({
        id:             t.id,
        nombre:         t.nombre,
        hora:           t.hora.slice(0, 5),
        servicio:       t.servicio_nombre,
        estado:         t.estado,
        pago_estado:    t.pago_estado    || "sin_pago",
        metodo_pago:    t.metodo_pago    || "none",
        precio_cobrado: t.precio_cobrado || 0,
    }));

    const desde90 = new Date(ahoraArg); desde90.setDate(desde90.getDate() - 90);
    const hasta7  = new Date(ahoraArg); hasta7.setDate(hasta7.getDate() + 7);
    const { data: turnosPago } = await supabase.from("turnos")
      .select("monto_pagado, pago_estado, fecha_pago, fecha, email, telefono, created_at")
      .eq("slug", slug)
      .gte("fecha", desde90.toISOString().split("T")[0])
      .lte("fecha", hasta7.toISOString().split("T")[0])
      .neq("pago_estado", "sin_pago");

    const metricas  = agruparPagos(turnosPago || [], hoyISO);
    const mesKey    = `${anioActual}-${String(mesActual).padStart(2, "0")}`;
    const pagosHoy  = metricas.porDia[hoyISO] || { volumen: 0, cantidad: 0, aprobado: 0, pendiente: 0, rechazado: 0 };
    const pagosMes  = metricas.porMes.find((m) => m.label === mesKey) || { volumen: 0, cantidad: 0 };

    const proximosDias = generarRangoDias(hoyISO, 7).map((fecha) => ({
      fecha, ...(metricas.porDia[fecha] || { volumen: 0, cantidad: 0, aprobado: 0, pendiente: 0, rechazado: 0 }),
    }));

    const { data: todosLosTurnos } = await supabase.from("turnos")
      .select("telefono, email, created_at").eq("slug", slug).neq("estado", "cancelado");
    const clientesUnicos = new Set(), clientesMesSet = new Set();
    const inicioMesDate  = new Date(inicioMes + "T00:00:00");
    (todosLosTurnos || []).forEach((t) => {
      const key = t.telefono || t.email?.toLowerCase();
      if (key) {
        clientesUnicos.add(key);
        if (new Date(t.created_at) >= inicioMesDate) clientesMesSet.add(key);
      }
    });

    const pagosPorDia = {};
    generarRangoDias(inicioMes, diaHoyNum).forEach((d) => {
      pagosPorDia[d] = metricas.porDia[d] || { volumen: 0, cantidad: 0, aprobado: 0, pendiente: 0, rechazado: 0 };
    });

    const diasRestantes      = user.fecha_vencimiento ? diasHastaVencer(user.fecha_vencimiento) : null;
    const estadoSuscripcion  = user.estado_suscripcion || "trial";
    const suscripcionVencida = diasRestantes !== null && diasRestantes <= 0;

    const finalData = {
      turnosHoy, turnosMes: turnosMesTotal, turnosHoyDetalle,
      chartData: Object.keys(semanas).map((k) => ({ label: k, turnos: semanas[k] })),
      turnosLista,
      totalClientes:        clientesUnicos.size,
      clientesNuevos:       clientesMesSet.size,
      clientesConcurrentes: Math.floor(clientesUnicos.size * 0.4),
      ventas: {
        volumenTotal:   metricas.volumenTotal,
        volumenHoy:     pagosHoy.volumen,
        volumenMes:     pagosMes.volumen  || 0,
        ticketPromedio: metricas.ticketPromedio,
        cantidadTotal:  metricas.cantidadTotal,
        cantidadHoy:    pagosHoy.cantidad,
        cantidadMes:    pagosMes.cantidad || 0,
        estados: { aprobado: metricas.porEstado.aprobado || 0, pendiente: metricas.porEstado.pendiente || 0, rechazado: metricas.porEstado.rechazado || 0 },
      },
      ventasPorDia: pagosPorDia,
      ventasPorSem: metricas.porSemana,
      ventasPorMes: metricas.porMes,
      proximosDias,
      horarios: user.horarios,
      config: {
        plan:                user.plan                || "gratis",
        duracion:            user.duracion_turno      || 30,
        capacidad_por_turno: user.capacidad_por_turno || 1,
        metodo_pago:         user.metodo_pago         || "none",
        porcentaje_sena:     user.porcentaje_sena     || 30,
        mp_status:           user.mp_access_token ? "Conectado" : "Desconectado",
        excepciones:         user.excepciones         || [],
      },
      suscripcion: {
        estado:            suscripcionVencida ? "suspendido" : estadoSuscripcion,
        fecha_vencimiento: user.fecha_vencimiento,
        dias_restantes:    diasRestantes,
        alerta:            diasRestantes !== null && diasRestantes <= 5 && diasRestantes > 0,
        vencida:           suscripcionVencida,
        precio_renovacion: PRECIO_RENOVACION,
      },
      businessName:   user.business_name,
      nombre_persona: user.nombre_persona,
      apellido:       user.apellido || "",
      slug:           user.slug,
      plan:           user.plan || "gratis",
    };

    globalCache[slug] = { timestamp: now, data: finalData };
    res.json(finalData);
  } catch (e) {
    console.error("Error en /admin-stats:", e.message);
    res.status(500).json({ success: false, error: "Error al procesar estadísticas." });
  }
});

// ══════════════════════════════════════════════════════════════
// SUPERADMIN — CRUD DE NEGOCIOS
// ══════════════════════════════════════════════════════════════
app.post("/superadmin/negocios", requireAdminKey, async (req, res) => {
  try {
    const { nombre_persona, apellido, email, telefono, business_name, password, plan = "gratis" } = req.body;
    if (!nombre_persona || !email || !password || !business_name) {
      return res.status(400).json({ success: false, error: "Faltan campos obligatorios." });
    }
    if (!validateEmail(email))       return res.status(400).json({ success: false, error: "Email inválido." });
    if (!validatePassword(password)) return res.status(400).json({ success: false, error: "Contraseña: mínimo 6 caracteres." });

    const planFinal         = plan === "premium" ? "premium" : "gratis";
    const slug              = await generarSlugUnico(business_name.trim());
    const hashedPassword    = await bcrypt.hash(String(password), BCRYPT_ROUNDS);
    const fechaVencimiento  = planFinal === "premium" ? calcularVencimiento(DIAS_PRUEBA) : null;
    const estadoSuscripcion = planFinal === "premium" ? "trial" : "activo";

    const { data, error } = await supabase.from("usuarios").insert([{
      nombre_persona: nombre_persona.trim(), apellido: apellido?.trim() || "",
      email: email.trim().toLowerCase(), telefono: telefono ? cleanPhone(telefono) : null,
      business_name: business_name.trim(), slug, password: hashedPassword,
      plan: planFinal,
      metodo_pago: "none", porcentaje_sena: 30, excepciones: [],
      activo: "true", estado_suscripcion: estadoSuscripcion, fecha_vencimiento: fechaVencimiento,
    }]).select("id, slug, business_name, plan, email, nombre_persona, apellido, estado_suscripcion, fecha_vencimiento").single();

    if (error) {
      if (error.code === "23505") return res.status(409).json({ success: false, error: "El email ya está registrado." });
      throw error;
    }
    res.status(201).json({ success: true, negocio: data, panel_url: `${PANEL_URL}?u=${slug}` });
  } catch (e) {
    res.status(500).json({ success: false, error: "No se pudo crear el negocio." });
  }
});

app.get("/superadmin/negocios", requireAdminKey, async (req, res) => {
  try {
    const { data, error } = await supabase.from("usuarios")
      .select("id, slug, business_name, nombre_persona, apellido, email, telefono, activo, plan, metodo_pago, mp_access_token, estado_suscripcion, fecha_vencimiento, created_at")
      .order("business_name", { ascending: true });
    if (error) throw error;
    const negocios = (data || []).map((u) => ({
      id: u.id, slug: u.slug, business_name: u.business_name,
      nombre_persona: u.nombre_persona, apellido: u.apellido,
      email: u.email, telefono: u.telefono,
      activo: isActivo(u.activo), plan: u.plan || "gratis",
      metodo_pago: u.metodo_pago, tiene_mp: !!u.mp_access_token,
      estado_suscripcion: u.estado_suscripcion || "trial",
      fecha_vencimiento:  u.fecha_vencimiento,
      dias_restantes: u.fecha_vencimiento ? diasHastaVencer(u.fecha_vencimiento) : null,
      creado: u.created_at,
    }));
    res.json({ success: true, negocios, total: negocios.length });
  } catch (e) {
    res.status(500).json({ success: false, error: "Error al obtener negocios." });
  }
});

app.put("/superadmin/negocios/:slug", requireAdminKey, async (req, res) => {
  try {
    const slug    = cleanSlug(req.params.slug);
    const allowed = ["nombre_persona", "apellido", "email", "telefono", "business_name", "duracion_turno", "capacidad_por_turno", "estado_suscripcion", "fecha_vencimiento"];
    const update  = {};
    allowed.forEach((key) => { if (req.body[key] !== undefined) update[key] = req.body[key]; });
    if (req.body.activo   !== undefined) update.activo = req.body.activo === true || req.body.activo === "true" ? "true" : "false";
    if (req.body.plan     !== undefined) update.plan   = ["gratis", "premium"].includes(req.body.plan) ? req.body.plan : "gratis";
    if (req.body.password)               update.password = await bcrypt.hash(String(req.body.password), BCRYPT_ROUNDS);
    if (req.body.sumar_dias && !isNaN(parseInt(req.body.sumar_dias))) {
      const { data: actual } = await supabase.from("usuarios").select("fecha_vencimiento").eq("slug", slug).maybeSingle();
      const base = actual?.fecha_vencimiento && new Date(actual.fecha_vencimiento) > new Date() ? actual.fecha_vencimiento : null;
      update.fecha_vencimiento  = calcularVencimiento(parseInt(req.body.sumar_dias), base);
      update.estado_suscripcion = "activo";
    }
    const { error } = await supabase.from("usuarios").update(update).eq("slug", slug);
    if (error) throw error;
    invalidateCache(slug);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ success: false, error: "No se pudo actualizar el negocio." });
  }
});

// ══════════════════════════════════════════════════════════════
// AUTH — Recuperación de contraseña
// ══════════════════════════════════════════════════════════════
app.post("/auth/forgot-password", limiterAuth, async (req, res) => {
  try {
    const email = req.body.email?.trim().toLowerCase();
    if (!email || !validateEmail(email))
      return res.status(400).json({ success: false, error: "Email inválido." });

    const { data: user } = await supabase
      .from("usuarios").select("id, nombre_persona, email")
      .eq("email", email).maybeSingle();

    if (!user)
      return res.json({ success: true, message: "Si el email existe, vas a recibir un enlace." });

    const token  = crypto.randomUUID();
    const expiry = new Date(Date.now() + 1000 * 60 * 30);

    await supabase.from("usuarios").update({
      reset_token:        token,
      reset_token_expiry: expiry.toISOString(),
    }).eq("id", user.id);

    const resetUrl = `https://turnits.com/cambiar-contraseña?token=${token}`;

    fetch(APPS_SCRIPT_URL, {
      method: "POST",
      headers: { "Content-Type": "text/plain" },
      body: JSON.stringify({ action: "resetPassword", email: user.email, nombre: user.nombre_persona, resetUrl }),
    }).catch((e) => console.error("Error mail reset:", e.message));

    res.json({ success: true, message: "Si el email existe, vas a recibir un enlace." });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.post("/auth/reset-password", limiterAuth, async (req, res) => {
  try {
    const { token, new_password } = req.body;
    if (!token || !new_password)
      return res.status(400).json({ success: false, error: "Faltan token y nueva contraseña." });
    if (!validatePassword(new_password))
      return res.status(400).json({ success: false, error: "Mínimo 6 caracteres." });

    const { data: user } = await supabase
      .from("usuarios").select("id, reset_token_expiry")
      .eq("reset_token", token).maybeSingle();

    if (!user)
      return res.status(400).json({ success: false, error: "Token inválido o ya usado." });
    if (new Date(user.reset_token_expiry) < new Date())
      return res.status(400).json({ success: false, error: "El token expiró. Solicitá uno nuevo." });

    const hash = await bcrypt.hash(String(new_password), BCRYPT_ROUNDS);
    await supabase.from("usuarios").update({ password: hash, reset_token: null, reset_token_expiry: null }).eq("id", user.id);

    res.json({ success: true, message: "Contraseña actualizada correctamente." });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.post("/auth/send-verification", requireAuth, async (req, res) => {
  try {
    const slug = cleanSlug(req.auth.slug);
    const { data: user } = await supabase
      .from("usuarios").select("id, email, nombre_persona, email_verificado")
      .eq("slug", slug).maybeSingle();

    if (!user) return res.status(404).json({ success: false, error: "Usuario no encontrado." });
    if (user.email_verificado) return res.json({ success: true, message: "El email ya está verificado." });

    const token = crypto.randomUUID();
    await supabase.from("usuarios").update({ verificacion_token: token }).eq("id", user.id);

    const verificarUrl = `${API_URL}/auth/verify-email?token=${token}`;
    fetch(APPS_SCRIPT_URL, {
      method: "POST",
      headers: { "Content-Type": "text/plain" },
      body: JSON.stringify({ action: "verificarEmail", email: user.email, nombre: user.nombre_persona, verificarUrl }),
    }).catch((e) => console.error("Error mail verificacion:", e.message));

    res.json({ success: true, message: "Email de verificación enviado." });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.get("/auth/verify-email", async (req, res) => {
  try {
    const { token } = req.query;
    if (!token) return res.redirect(`${PANEL_URL}?status=verificacion_error`);

    const { data: user } = await supabase
      .from("usuarios").select("id, slug")
      .eq("verificacion_token", token).maybeSingle();

    if (!user) return res.redirect(`${PANEL_URL}?status=verificacion_error`);

    await supabase.from("usuarios").update({ email_verificado: true, verificacion_token: null }).eq("id", user.id);
    invalidateCache(user.slug);
    res.redirect(`${PANEL_URL}?status=verificacion_ok&u=${user.slug}`);
  } catch (e) {
    res.redirect(`${PANEL_URL}?status=verificacion_error`);
  }
});

app.get("/auth/reset-token-info", async (req, res) => {
  try {
    const { token } = req.query;
    if (!token) return res.status(400).json({ success: false, error: "Token requerido." });

    const { data: user } = await supabase
      .from("usuarios").select("slug, nombre_persona, reset_token_expiry")
      .eq("reset_token", token).maybeSingle();

    if (!user) return res.status(400).json({ success: false, error: "Token inválido o ya usado." });
    if (new Date(user.reset_token_expiry) < new Date())
      return res.status(400).json({ success: false, error: "El token expiró." });

    res.json({ success: true, slug: user.slug, nombre: user.nombre_persona });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// ══════════════════════════════════════════════════════════════
// PAGOS — Mercado Pago
// POST /api/create-preference
// FIX: ahora se guarda un registro en pagos_pendientes con un
// external_reference único ANTES de crear la preferencia. El webhook
// usa ese registro para resolver el slug/datos del turno sin
// depender únicamente de que el token de plataforma pueda leer
// el pago del vendedor.
// ══════════════════════════════════════════════════════════════
app.post("/api/create-preference", limiterBooking, async (req, res) => {
  console.log("📥 create-preference body:", JSON.stringify(req.body));
  try {
    const { nombre, telefono, email, fecha, hora, slug, servicio_id, apellido, extra_ids } = req.body;
    const slugClean = cleanSlug(slug || "");
    if (!nombre || !telefono || !fecha || !hora || !slugClean) {
      return res.status(400).json({ success: false, error: "Faltan datos requeridos." });
    }

    const { data: user, error: userError } = await supabase.from("usuarios").select("*").eq("slug", slugClean).maybeSingle();
    if (userError) throw userError;
    if (!user) return res.status(404).json({ success: false, error: "Negocio no encontrado." });

    const diasRestantes  = user.fecha_vencimiento ? diasHastaVencer(user.fecha_vencimiento) : null;
    const estaSuspendido = user.estado_suscripcion === "suspendido" || (diasRestantes !== null && diasRestantes <= 0);
    if (estaSuspendido) return res.status(403).json({ success: false, error: "Este servicio está pausado temporalmente." });

let precioServicio = 0, nombreServicio = "Reserva";
if (servicio_id) {
  const { data: srv } = await supabase.from("servicios").select("nombre, precio").eq("id", servicio_id).eq("slug", slugClean).maybeSingle();
  if (srv) { precioServicio = Number(srv.precio || 0); nombreServicio = srv.nombre; }
}

const { extras: extrasResueltos, montoExtras } = await resolverExtras(slugClean, servicio_id || null, extra_ids);

const metodo    = user.metodo_pago || "none";
const debePagar = metodo === "sena" || metodo === "total";
if (!debePagar || (precioServicio <= 0 && montoExtras <= 0)) return res.json({ isFree: true });

const montoServicio = metodo === "sena"
  ? Math.round(precioServicio * (user.porcentaje_sena || 30) / 100)
  : precioServicio;
const conceptoPago = metodo === "sena" ? `Seña ${user.porcentaje_sena || 30}%` : "Total";

const montoACobrar = montoServicio + montoExtras;   // ← total real: servicio + productos
const fee = Math.max(300, Math.round(montoACobrar * 0.02));

if (user.mp_access_token) {
  try {
    const metaPendiente = {
      slug: slugClean,
      nombre, telefono: cleanPhone(telefono), email: email || "",
      apellido: apellido || "", fecha, hora,
      servicio_id: servicio_id || null, servicio_nombre: nombreServicio,
      precio_servicio: precioServicio, metodo_pago: metodo, monto: montoACobrar,
      extras: extrasResueltos, monto_extras: montoExtras,   // ← nuevo
      estado: "pendiente",
    };
    const { data: pendiente, error: pendError } = await supabase
      .from("pagos_pendientes").insert([metaPendiente]).select("id").single();
    if (pendError) throw pendError;

    const client = new MercadoPagoConfig({ accessToken: user.mp_access_token });
    const pref   = new Preference(client);

        const items = [
      { title: `${nombreServicio} (${conceptoPago}): ${fecha} - ${hora}hs`, unit_price: montoServicio, quantity: 1, currency_id: "ARS" },
      ...extrasResueltos.map((e) => ({ title: e.nombre, unit_price: e.precio, quantity: 1, currency_id: "ARS" })),
    ];
    const prefBody = {
      items,
      metadata: metaPendiente,
      external_reference: pendiente.id,
      notification_url: `${API_URL}/webhook/mp`,
      back_urls: { success: `${SUCCESS_URL}?slug=${slugClean}`, failure: `${ERROR_URL}?slug=${slugClean}`, pending: `${ERROR_URL}?slug=${slugClean}` },
      auto_return: "approved",
    };
        if (fee > 0) prefBody.marketplace_fee = fee;
        const response = await pref.create({ body: prefBody });

        await supabase.from("pagos_pendientes").update({ preference_id: response.id }).eq("id", pendiente.id);

        console.log(`💰 Preference creada: monto=${montoACobrar} fee=${fee} slug=${slugClean} ref=${pendiente.id}`);
        return res.json({ payment_url: response.init_point, monto: montoACobrar, fee, pasarela: "mercadopago" });
      } catch (e) {
        console.error("❌ MP error:", JSON.stringify(e));
        return res.status(500).json({ success: false, error: e?.message || "Error con MercadoPago." });
      }
    }

    res.status(400).json({ success: false, error: "Sin pasarela de pago configurada." });
  } catch (e) {
    console.error("❌ Error general:", e?.message);
    res.status(500).json({ success: false, error: e?.message || "Error interno." });
  }
});

// ══════════════════════════════════════════════════════════════
// RENOVACIÓN
// ══════════════════════════════════════════════════════════════
app.get("/renovacion/info/:slug", async (req, res) => {
  try {
    const slug = cleanSlug(req.params.slug);
    if (!slug) return res.status(400).json({ success: false, error: "Slug inválido." });

    const { data: user, error } = await supabase.from("usuarios")
      .select("slug, business_name, nombre_persona, plan, estado_suscripcion, fecha_vencimiento")
      .eq("slug", slug).maybeSingle();

    if (error) throw error;
    if (!user) return res.status(404).json({ success: false, error: "Negocio no encontrado." });

    const diasRestantes      = user.fecha_vencimiento ? diasHastaVencer(user.fecha_vencimiento) : null;
    const suscripcionVencida = diasRestantes !== null && diasRestantes <= 0;

    res.json({
      success: true, slug: user.slug, business_name: user.business_name,
      nombre_persona: user.nombre_persona, plan: user.plan || "gratis",
      estado: suscripcionVencida ? "suspendido" : (user.estado_suscripcion || "activo"),
      fecha_vencimiento: user.fecha_vencimiento, dias_restantes: diasRestantes,
      vencida: suscripcionVencida, precio_renovacion: PRECIO_RENOVACION,
    });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.post("/renovacion/checkout/:slug", async (req, res) => {
  try {
    const slug = cleanSlug(req.params.slug);
    if (!slug) return res.status(400).json({ success: false, error: "Slug inválido." });
    if (!MP_PLATFORM_TOKEN) return res.status(500).json({ success: false, error: "Pasarela de renovación no configurada." });

    const { data: user, error } = await supabase.from("usuarios")
      .select("id, email, nombre_persona, apellido, business_name, plan, fecha_vencimiento")
      .eq("slug", slug).maybeSingle();

    if (error) throw error;
    if (!user) return res.status(404).json({ success: false, error: "Negocio no encontrado." });

    const client   = new MercadoPagoConfig({ accessToken: MP_PLATFORM_TOKEN });
    const pref     = new Preference(client);
    const response = await pref.create({ body: {
      items: [{ title: `Turnits — Suscripción Premium (${user.business_name})`, unit_price: PRECIO_RENOVACION, quantity: 1, currency_id: "ARS" }],
      payer: { email: user.email, name: `${user.nombre_persona || ""} ${user.apellido || ""}`.trim() },
      metadata: { tipo: "renovacion_associe", slug, user_id: user.id },
      notification_url: `${API_URL}/webhook/renovacion`,
      back_urls: { success: RENOVACION_SUCCESS, failure: RENOVACION_CANCEL, pending: RENOVACION_CANCEL },
      auto_return: "approved",
    }});

    res.json({ success: true, payment_url: response.init_point, monto: PRECIO_RENOVACION });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// FIX: protegido — antes era público y cualquiera con el slug podía
// bajar a un negocio a plan gratis. Lo usa el owner desde el panel.
app.post("/renovacion/downgrade/:slug", requireAuth, async (req, res) => {
  try {
    const slug = cleanSlug(req.params.slug);
    if (!slug) return res.status(400).json({ success: false, error: "Slug inválido." });

    const { data: user, error: fetchError } = await supabase.from("usuarios")
      .select("id, slug").eq("slug", slug).maybeSingle();

    if (fetchError) throw fetchError;
    if (!user) return res.status(404).json({ success: false, error: "Negocio no encontrado." });

    const { error: updateError } = await supabase.from("usuarios").update({
      plan:               "gratis",
      estado_suscripcion: "activo",
      fecha_vencimiento:  null,
      metodo_pago:        "total",
    }).eq("slug", slug);

    if (updateError) throw updateError;
    invalidateCache(slug);
    console.log(`⬇️  Downgrade a gratis: ${slug}`);
    res.json({ success: true, plan: "gratis", mensaje: "Plan cambiado a gratuito correctamente." });
  } catch (e) {
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
    const slugClean = cleanSlug(slug);
    const response  = await fetch("https://api.mercadopago.com/oauth/token", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ client_id: process.env.MP_TURNERO_CLIENT_ID, client_secret: process.env.MP_TURNERO_CLIENT_SECRET, grant_type: "authorization_code", code, redirect_uri: `${API_URL}/oauth-callback` }),
    });
    const data = await response.json();
    console.log("🔑 OAuth response:", JSON.stringify(data));
    if (data.access_token) {
      const { error: updError } = await supabase.from("usuarios")
        .update({ mp_access_token: data.access_token, mp_public_key: data.public_key || null })
        .eq("slug", slugClean);
      if (updError) { console.error("Error guardando token MP:", updError.message); return res.redirect(`${PANEL_URL}?status=mp_error&u=${slugClean}`); }
      invalidateCache(slugClean);

      crearNotificacion({
        slug: slugClean,
        tipo: "sistema",
        titulo: "Mercado Pago conectado",
        mensaje: "Ya podés cobrar señas o el total de tus turnos desde el link de reserva.",
        data: { clave: "mp_conectado" },
      });

      return res.redirect(`${PANEL_URL}?status=mp_success&u=${slugClean}`);
    }
    res.redirect(`${PANEL_URL}?status=mp_error&u=${slugClean}`);
  } catch (e) {
    res.status(500).send("Error al vincular Mercado Pago.");
  }
});

// ══════════════════════════════════════════════════════════════
// WEBHOOKS
// FIX (sobreventa): si el cupo está lleno, NO se inserta el turno.
// Se loguea como conflicto y se avisa al admin para que reprograme
// o reembolse manualmente, en vez de confirmar un turno por encima
// de la capacidad.
// ══════════════════════════════════════════════════════════════
async function procesarPagoConfirmado({ slug, nombre, apellido, telefono, email, fecha, hora, servicio_id, servicio_nombre, monto, moneda, metodo_pago, precio_servicio, payment_id, estado, porcentaje_sena, extras, monto_extras }) {
  const { data: turnoExistente } = await supabase
    .from("turnos").select("id").eq("payment_id", String(payment_id)).maybeSingle();
  if (turnoExistente) { console.log(`⚠️ Pago ${payment_id} ya procesado, ignorando.`); return; }

  const { data: user } = await supabase.from("usuarios")
    .select("email, business_name, porcentaje_sena, capacidad_por_turno").eq("slug", slug).maybeSingle();

  const porcSena   = porcentaje_sena || user?.porcentaje_sena || 30;
  const pagoEstado = estado === "aprobado" ? "aprobado" : estado === "pendiente" ? "pendiente" : "rechazado";

  if (estado === "aprobado") {
    const capacidad = user?.capacidad_por_turno || 1;
    const { count } = await supabase.from("turnos").select("id", { count: "exact" })
      .eq("slug", slug).eq("fecha", fecha).eq("hora", hora).neq("estado", "cancelado");

    if (count >= capacidad) {
      console.error(`🚫 SOBREVENTA bloqueada: turno ${fecha} ${hora} lleno para ${slug}, payment_id ${payment_id}. NO se confirma el turno, requiere intervención manual.`);
      enviarMailConflictoTurno({
        adminEmail: user?.email,
        nombreCliente: nombre?.trim() || "Cliente",
        fechaHora: `${fecha} ${hora}`,
        slug, payment_id, monto,
      });

      crearNotificacion({
        slug,
        tipo: "sistema",
        titulo: "⚠️ Conflicto de sobreventa",
        mensaje: `Un pago de ${nombre?.trim() || "un cliente"} se aprobó para el ${fecha} ${hora}hs pero el cupo ya estaba lleno. Requiere que lo revises manualmente.`,
        data: { fecha, hora, payment_id, monto },
      });

      invalidateCache(slug);
      return;
    }

const { error: turnoError } = await supabase.from("turnos").insert([{
      slug, nombre: nombre?.trim() || "Cliente", apellido: apellido?.trim() || null,
      telefono: cleanPhone(telefono?.toString() || "0"), email: email?.trim().toLowerCase() || null,
      fecha, hora, servicio_id: servicio_id || null, servicio_nombre: servicio_nombre || null,
      precio_cobrado: Number(precio_servicio || 0) + Number(monto_extras || 0),  // ← total real
      monto_pagado: monto,
      extras: extras || [],            // ← nuevo
      monto_extras: monto_extras || 0, // ← nuevo
      porcentaje_sena: metodo_pago === "sena" ? porcSena : null,
      metodo_pago, pago_estado: pagoEstado, fecha_pago: new Date().toISOString(),
      moneda: moneda || "ARS", estado: "confirmado", payment_id: String(payment_id),
    }]);

    if (turnoError) {
      if (turnoError.code === "23505") { console.log(`⚠️ Turno duplicado bloqueado por DB: ${payment_id}`); }
      else throw turnoError;
    } else {
      if (user?.email) {
        enviarMailTurno({
          adminEmail:    user.email,
          emailCliente:  email?.trim().toLowerCase() || "",
          nombreCliente: nombre?.trim() || "Cliente",
          fechaHora:     `${fecha} ${hora}`,
          slug, servicio: servicio_nombre || "",
          precioTotal:   Number(precio_servicio || monto || 0),
          montoOnline:   Number(monto || 0),
          metodoPago:    metodo_pago || "mercadopago",
        });
      }

      // Confirmación por WhatsApp al cliente (independiente del email)
      enviarWhatsappTurno({
        telefono:      telefono,
        nombreCliente: nombre?.trim() || "Cliente",
        businessName:  user?.business_name,
        fechaHora:     `${fecha} ${hora}`,
        servicio:      servicio_nombre || "",
      });

      // Notificación in-app: turno pagado (una sola, con servicio + monto)
      crearNotificacion({
        slug,
        tipo: "pago_aprobado",
        titulo: "Turno pagado",
        mensaje: `${nombre?.trim() || "Cliente"} pagó ${metodo_pago === "sena" ? "la seña" : "el turno completo"} (${servicio_nombre ? servicio_nombre + " — " : ""}$${monto}) para el ${fecha} a las ${hora}hs.`,
        data: { fecha, hora, monto },
      });
    }
  }

  invalidateCache(slug);
  console.log(`✅ Pago procesado: ${payment_id} — slug: ${slug} — estado: ${pagoEstado}`);
}

// FIX: el webhook ahora resuelve el slug primero contra pagos_pendientes
// (vía external_reference), que es más confiable que depender de que
// el MP_PLATFORM_TOKEN pueda leer la metadata del pago del vendedor.
app.post("/webhook/mp", async (req, res) => {
  const { query, body } = req;
  try {
    if (query.topic === "payment" || body.type === "payment") {
      const paymentId = query.id || body.data?.id;
      if (!paymentId) return res.sendStatus(200);

      const payRes  = await fetch(`https://api.mercadopago.com/v1/payments/${paymentId}`, { headers: { Authorization: `Bearer ${MP_PLATFORM_TOKEN}` } });
      const payData = await payRes.json();

      if (payData.metadata?.tipo === "renovacion_associe") { await procesarRenovacion(payData); return res.sendStatus(200); }

      // 1) Intentar resolver por external_reference contra pagos_pendientes (fuente confiable)
      let pendiente = null;
      const externalRef = payData.external_reference || body.external_reference;
      if (externalRef) {
        const { data } = await supabase.from("pagos_pendientes").select("*").eq("id", externalRef).maybeSingle();
        pendiente = data;
      }

      // 2) Fallback a metadata si no hay pendiente (ej. pagos viejos antes de este fix)
      const slug = cleanSlug(pendiente?.slug || payData.metadata?.slug || "");
      if (!slug) {
        console.error(`⚠️ Webhook MP: no se pudo resolver el slug para payment ${paymentId}. external_reference=${externalRef}`);
        return res.sendStatus(200);
      }

      const { data: userNegocio } = await supabase.from("usuarios").select("mp_access_token").eq("slug", slug).maybeSingle();

      // 3) Releer el pago con el token del vendedor para confirmar estado/monto reales
      let finalPayData = payData;
      if (userNegocio?.mp_access_token) {
        try {
          const vendorRes  = await fetch(`https://api.mercadopago.com/v1/payments/${paymentId}`, { headers: { Authorization: `Bearer ${userNegocio.mp_access_token}` } });
          const vendorData = await vendorRes.json();
          if (vendorData?.id) finalPayData = vendorData;
        } catch (e) {
          console.error("No se pudo releer el pago con token del vendedor, se usa data de plataforma:", e.message);
        }
      }

      const meta   = pendiente || finalPayData.metadata || {};
      const estado = finalPayData.status === "approved" ? "aprobado" : finalPayData.status === "pending" ? "pendiente" : "rechazado";

      await procesarPagoConfirmado({
        slug,
        nombre:           meta.nombre,
        apellido:         meta.apellido || null,
        telefono:         meta.telefono,
        email:            meta.email,
        fecha:            meta.fecha,
        hora:             meta.hora,
        servicio_id:      meta.servicio_id || null,
        servicio_nombre:  meta.servicio_nombre || null,
        monto:            Number(finalPayData.transaction_amount || meta.monto || 0),
        moneda:           finalPayData.currency_id || "ARS",
        metodo_pago:      meta.metodo_pago || "mercadopago",
        precio_servicio:  meta.precio_servicio || null,
        payment_id:       paymentId,
        estado,
        extras: meta.extras || [],
        monto_extras: meta.monto_extras || 0
      });

      if (pendiente) {
        await supabase.from("pagos_pendientes")
          .update({ estado, payment_id: String(paymentId) })
          .eq("id", pendiente.id);
      }
    }
    res.sendStatus(200);
  } catch (e) {
    console.error("Error en /webhook/mp:", e.message);
    res.sendStatus(200);
  }
});

async function procesarRenovacion(payData) {
  if (payData.status !== "approved") return;
  const slug = cleanSlug(payData.metadata?.slug || "");
  if (!slug) return;
  const { data: user } = await supabase.from("usuarios")
    .select("id, email, nombre_persona, plan, fecha_vencimiento").eq("slug", slug).maybeSingle();
  if (!user) return;

  const fechaBase  = user.fecha_vencimiento && new Date(user.fecha_vencimiento) > new Date() ? user.fecha_vencimiento : null;
  const nuevaFecha = calcularVencimiento(30, fechaBase);

  await supabase.from("usuarios").update({ fecha_vencimiento: nuevaFecha, estado_suscripcion: "activo", plan: "premium" }).eq("slug", slug);
  invalidateCache(slug);
  console.log(`✅ Renovación aprobada: ${slug} → vence ${nuevaFecha}`);

  if (user.email) {
    fetch(APPS_SCRIPT_URL, {
      method: "POST", headers: { "Content-Type": "text/plain" },
      body: JSON.stringify({ action: "renovacionAprobada", adminEmail: user.email, nombre: user.nombre_persona || "Cliente", slug, nuevaFecha }),
    }).catch((e) => console.error("Error mail renovación:", e.message));
  }

  crearNotificacion({
    slug,
    tipo: "sistema",
    titulo: "Renovación aprobada",
    mensaje: `Tu plan Premium se renovó correctamente. Nueva fecha de vencimiento: ${nuevaFecha}.`,
    data: { nuevaFecha },
  });
}

app.post("/webhook/renovacion", async (req, res) => {
  const { query, body } = req;
  try {
    if (query.topic === "payment" || body.type === "payment") {
      const paymentId = query.id || body.data?.id;
      if (!paymentId) return res.sendStatus(200);
      const payRes = await fetch(`https://api.mercadopago.com/v1/payments/${paymentId}`, { headers: { Authorization: `Bearer ${MP_PLATFORM_TOKEN}` } });
      await procesarRenovacion(await payRes.json());
    }
    res.sendStatus(200);
  } catch (e) {
    console.error("Error en /webhook/renovacion:", e.message);
    res.sendStatus(200);
  }
});

// ══════════════════════════════════════════════════════════════
// WEBHOOK — WhatsApp Cloud API (Meta)
// GET  → handshake de verificación que pide Meta al configurar el
//        webhook en Meta for Developers (App > WhatsApp > Configuración).
// POST → eventos entrantes: mensajes de clientes y actualizaciones
//        de estado de los mensajes que mandamos (entregado/leído).
//        No hace nada crítico todavía, solo loguea — es la base
//        para eventualmente responder consultas por WhatsApp.
// ══════════════════════════════════════════════════════════════
app.get("/webhook/whatsapp", (req, res) => {
  const mode      = req.query["hub.mode"];
  const token     = req.query["hub.verify_token"];
  const challenge = req.query["hub.challenge"];

  if (mode === "subscribe" && token && WHATSAPP_VERIFY_TOKEN && token === WHATSAPP_VERIFY_TOKEN) {
    console.log("✅ Webhook de WhatsApp verificado por Meta.");
    return res.status(200).send(challenge);
  }
  res.sendStatus(403);
});

app.post("/webhook/whatsapp", (req, res) => {
  try {
    const entry  = req.body?.entry?.[0];
    const change = entry?.changes?.[0]?.value;

    const mensajes = change?.messages;
    if (mensajes?.length) {
      mensajes.forEach((m) => {
        console.log(`📩 WhatsApp de ${m.from}: ${m.text?.body || `[${m.type}]`}`);
      });
    }

    const estados = change?.statuses;
    if (estados?.length) {
      estados.forEach((s) => {
        console.log(`📶 WhatsApp status: ${s.id} → ${s.status}`);
      });
    }
  } catch (e) {
    console.error("Error en /webhook/whatsapp:", e.message);
  }
  // Meta espera siempre 200, incluso si algo falla al procesar.
  res.sendStatus(200);
});

// ══════════════════════════════════════════════════════════════
// ADMIN — Test de envío por WhatsApp
// POST /admin/whatsapp/test
// Útil para probar que el token, el phone_number_id y la plantilla
// están bien configurados antes de depender de esto en producción.
// ══════════════════════════════════════════════════════════════
app.post("/admin/whatsapp/test", requireAdminKey, async (req, res) => {
  try {
    const { telefono, nombre, businessName, servicio, fechaHora } = req.body;
    if (!telefono) return res.status(400).json({ success: false, error: "Falta el teléfono." });
    if (!WHATSAPP_HABILITADO) return res.status(400).json({ success: false, error: "WhatsApp no está configurado (faltan variables de entorno)." });

    const resultado = await enviarWhatsapp(telefono, WHATSAPP_TEMPLATE_TURNO, [
      {
        type: "body",
        parameters: [
          { type: "text", text: nombre       || "Cliente de prueba" },
          { type: "text", text: businessName || "Turnits" },
          { type: "text", text: servicio     || "Corte de pelo" },
          { type: "text", text: fechaHora    || new Date().toLocaleString("es-AR") },
        ],
      },
    ]);

    res.json({ success: !!resultado.success, resultado });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// ══════════════════════════════════════════════════════════════
// CRON — Verificación de vencimientos
// Además de suspender/reactivar negocios, ahora genera una
// notificación in-app cuando faltan 5 días o 1 día para vencer.
// ══════════════════════════════════════════════════════════════
app.get("/cron/check-vencimientos", requireAdminKey, async (req, res) => {
  try {
    const hoyISO = new Date(new Date().toLocaleString("en-US", { timeZone: "America/Argentina/Buenos_Aires" })).toISOString().split("T")[0];

    const { data: vencidos, error } = await supabase.from("usuarios")
      .select("id, slug").eq("activo", "true").neq("estado_suscripcion", "suspendido")
      .not("fecha_vencimiento", "is", null).lt("fecha_vencimiento", hoyISO);
    if (error) throw error;

    const slugs = (vencidos || []).map((u) => u.slug);
    if (slugs.length > 0) {
      await supabase.from("usuarios").update({ estado_suscripcion: "suspendido" }).in("slug", slugs);
      slugs.forEach((s) => invalidateCache(s));
    }

    const { data: reactivables } = await supabase.from("usuarios")
      .select("id, slug").eq("activo", "true").eq("estado_suscripcion", "suspendido")
      .not("fecha_vencimiento", "is", null).gte("fecha_vencimiento", hoyISO);
    const slugsReactivar = (reactivables || []).map((u) => u.slug);
    if (slugsReactivar.length > 0) {
      await supabase.from("usuarios").update({ estado_suscripcion: "activo" }).in("slug", slugsReactivar);
      slugsReactivar.forEach((s) => invalidateCache(s));
    }

    // Avisos in-app para negocios que están por vencer (5 días o 1 día)
    const { data: porVencer } = await supabase.from("usuarios")
      .select("slug, fecha_vencimiento").eq("activo", "true").eq("estado_suscripcion", "activo")
      .not("fecha_vencimiento", "is", null);

    const avisados = [];
    for (const u of (porVencer || [])) {
      const dias = diasHastaVencer(u.fecha_vencimiento);
      if (dias === 5 || dias === 1) {
        await crearNotificacion({
          slug: u.slug,
          tipo: "vencimiento",
          titulo: "Tu suscripción está por vencer",
          mensaje: dias === 1
            ? "Tu plan Premium vence mañana. Renová para no perder acceso al panel."
            : "Tu plan Premium vence en 5 días. Renová cuando quieras desde el panel.",
          data: { fecha_vencimiento: u.fecha_vencimiento, dias_restantes: dias },
        });
        avisados.push(u.slug);
      }
    }

    res.json({ success: true, fecha: hoyISO, suspendidos: slugs, reactivados: slugsReactivar, avisados_vencimiento: avisados });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// ══════════════════════════════════════════════════════════════
// CRON — Generar tips para negocios existentes
// Corré esto una vez por día (o por semana) para que los negocios
// ya creados también reciban recomendaciones, no solo los nuevos.
// ══════════════════════════════════════════════════════════════
app.get("/cron/generar-tips", requireAdminKey, async (req, res) => {
  try {
    const { data: negocios, error } = await supabase.from("usuarios")
      .select("slug").eq("activo", "true");
    if (error) throw error;

    for (const n of (negocios || [])) {
      await generarTips(n.slug);
    }
    res.json({ success: true, procesados: (negocios || []).length });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
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
  ║   Turnits API v13.7                            ║
  ║   Nuevo: bandeja de entrada / notificaciones   ║
  ║   in-app (Realtime) + tips de buenas prácticas ║
  ║   WhatsApp (${WHATSAPP_HABILITADO ? "configurada" : "SIN configurar"})               ║
  ║   Puerto: ${PORT}                              ║
  ╚═══════════════════════════════════════════════╝
  `);
});

export default app;
