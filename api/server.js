import express from "express";
import cors from "cors";
import { createClient } from "@supabase/supabase-js";
import { google } from "googleapis";
import { MercadoPagoConfig, Preference } from "mercadopago";
import Stripe from "stripe";
import fetch from "node-fetch";
import crypto from "crypto";
 
const app = express();
 
// ─── CONFIGURACIÓN GLOBAL ────────────────────────────────────────────────────
const MASTER_SHEET_ID = "1CYF1IJFEKibbkXTKco-o13ZbMo6KpkT5oJj35Z3q4hg";
const APPS_SCRIPT_URL =
  "https://script.google.com/macros/s/AKfycbzvcaYhHuyD-Xu63Aw9WpWrpcr5xmrgHW_IffXkmC90bs0pTzhWP1d8rWBaBuhG5Icx/exec";
 
app.use(
  cors({
    origin: [
      "https://negosocio.framer.website",
      "https://framerturnero.onrender.com",
    ],
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);
app.use(express.json());
 
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_KEY
);
 
// ─── CACHÉ EN MEMORIA ────────────────────────────────────────────────────────
const globalCache = {};
const CACHE_DURATION = 20000;
 
// ─── HELPERS ─────────────────────────────────────────────────────────────────
const getCleanSlug = (rawSlug) => {
  if (!rawSlug) return "";
  return rawSlug
    .toLowerCase()
    .trim()
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/\s+/g, "-")
    .replace(/[^a-z0-9-]/g, "");
};
 
async function getGoogleAuth() {
  return new google.auth.GoogleAuth({
    credentials: {
      client_email: process.env.GOOGLE_SERVICE_ACCOUNT_EMAIL,
      private_key: process.env.GOOGLE_PRIVATE_KEY.replace(/\\n/g, "\n"),
    },
    scopes: ["https://www.googleapis.com/auth/spreadsheets"],
  });
}
 
async function getSheets() {
  const auth = await getGoogleAuth();
  const client = await auth.getClient();
  return google.sheets({ version: "v4", auth: client });
}
 
// ─── RUTA RAÍZ ───────────────────────────────────────────────────────────────
app.get("/", (req, res) => {
  res.send("NegoSocio API — Online");
});
 
// ─── PAGOS: MERCADO PAGO Y STRIPE ────────────────────────────────────────────
 
// POST /api/create-preference
// Crea una preferencia de pago (seña o total) con MP o Stripe según config del negocio.
app.post("/api/create-preference", async (req, res) => {
  try {
    const { nombre, telefono, email, fecha, hora, slug, servicio_id } =
      req.body;
    const cleanSlug = getCleanSlug(slug);
 
    const { data: user, error: userError } = await supabase
      .from("usuarios")
      .select("*")
      .eq("slug", cleanSlug)
      .single();
 
    if (userError || !user) {
      return res.status(404).json({ error: "Negocio no encontrado." });
    }
 
    // Precio y concepto: servicio específico tiene prioridad sobre precio global
    let precioFinal = Number(user.precio || 0);
    let nombreServicio = "Reserva";
 
    if (servicio_id) {
      const { data: servicio } = await supabase
        .from("servicios")
        .select("*")
        .eq("id", servicio_id)
        .single();
 
      if (servicio) {
        precioFinal = Number(servicio.precio || precioFinal);
        nombreServicio = servicio.nombre || nombreServicio;
      }
    }
 
    // Si el método es seña, usamos monto_sena
    if (user.metodo_pago === "sena" && user.monto_sena) {
      precioFinal = Number(user.monto_sena);
    }
 
    const metodo = user.metodo_pago || "none";
    const debePagar = metodo === "sena" || metodo === "total";
 
    if (!debePagar || precioFinal <= 0) {
      return res.json({ isFree: true });
    }
 
    const conceptoPago = metodo === "sena" ? "Seña" : "Total";
 
    // ── STRIPE ──
    if (user.stripe_secret_key) {
      const stripe = new Stripe(user.stripe_secret_key);
      const session = await stripe.checkout.sessions.create({
        payment_method_types: ["card"],
        line_items: [
          {
            price_data: {
              currency: "ars",
              product_data: {
                name: `${nombreServicio} (${conceptoPago}): ${fecha} a las ${hora}hs`,
              },
              unit_amount: Math.round(precioFinal * 100),
            },
            quantity: 1,
          },
        ],
        mode: "payment",
        metadata: {
          nombre,
          telefono,
          email: email || "",
          fecha,
          hora,
          slug: cleanSlug,
          servicio_id: servicio_id || "",
          metodo_pago: metodo,
        },
        success_url: "https://negosocio.framer.website/success",
        cancel_url: "https://negosocio.framer.website/error",
      });
      return res.json({ payment_url: session.url });
    }
 
    // ── MERCADO PAGO ──
    if (user.mp_access_token) {
      const client = new MercadoPagoConfig({
        accessToken: user.mp_access_token,
      });
      const preference = new Preference(client);
      const response = await preference.create({
        body: {
          items: [
            {
              title: `${nombreServicio} (${conceptoPago}): ${fecha} - ${hora}hs`,
              unit_price: precioFinal,
              quantity: 1,
              currency_id: "ARS",
            },
          ],
          metadata: {
            nombre,
            telefono,
            email: email || "",
            fecha,
            hora,
            slug: cleanSlug,
            servicio_id: servicio_id || "",
            tipo_pago: metodo,
          },
          notification_url:
            "https://framerturnero.onrender.com/webhook",
          back_urls: {
            success: "https://negosocio.framer.website/success",
            failure: "https://negosocio.framer.website/error",
            pending: "https://negosocio.framer.website/error",
          },
          auto_return: "approved",
        },
      });
      return res.json({ payment_url: response.init_point });
    }
 
    return res
      .status(400)
      .json({ error: "El negocio no tiene método de pago configurado." });
  } catch (e) {
    console.error("Error en /api/create-preference:", e.message);
    res.status(500).json({ error: e.message });
  }
});
 
// ─── MERCADO PAGO: OAUTH ──────────────────────────────────────────────────────
 
// GET /oauth-callback
// Recibe el code de MP y guarda el access_token del negocio en Supabase.
app.get("/oauth-callback", async (req, res) => {
  const { code, state: slug } = req.query;
 
  if (!code || !slug) {
    return res.status(400).send("Parámetros inválidos.");
  }
 
  try {
    const response = await fetch("https://api.mercadopago.com/oauth/token", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client_id: process.env.MP_TURNERO_CLIENT_ID,
        client_secret: process.env.MP_TURNERO_CLIENT_SECRET,
        grant_type: "authorization_code",
        code,
        redirect_uri: "https://framerturnero.onrender.com/oauth-callback",
      }),
    });
 
    const data = await response.json();
 
    if (data.access_token) {
      const { error } = await supabase
        .from("usuarios")
        .update({ mp_access_token: data.access_token })
        .eq("slug", slug);
 
      if (error) {
        return res.redirect(
          `https://negosocio.framer.website/dashboard?status=mp_error&u=${slug}`
        );
      }
 
      console.log(`MP vinculado para: ${slug}`);
      return res.redirect(
        `https://negosocio.framer.website/dashboard?status=mp_success&u=${slug}`
      );
    }
 
    res.redirect(
      `https://negosocio.framer.website/dashboard?status=mp_error&u=${slug}`
    );
  } catch (e) {
    console.error("Error en OAuth MP:", e.message);
    res.status(500).send("Error interno al vincular la cuenta.");
  }
});
 
// ─── WEBHOOK: PAGOS APROBADOS ─────────────────────────────────────────────────
 
// POST /webhook
// Recibe notificaciones de MP. Si el pago es aprobado, guarda el turno en Sheets.
app.post("/webhook", async (req, res) => {
  const { query, body } = req;
 
  try {
    if (query.topic === "payment" || body.type === "payment") {
      const paymentId = query.id || body.data?.id;
 
      if (paymentId) {
        // Primera consulta con token global para obtener el slug del metadata
        const paymentResponse = await fetch(
          `https://api.mercadopago.com/v1/payments/${paymentId}`,
          { headers: { Authorization: `Bearer ${process.env.MP_ACCESS_TOKEN}` } }
        );
        const paymentData = await paymentResponse.json();
 
        if (
          paymentData.status === "approved" &&
          paymentData.metadata?.slug
        ) {
          const slug = getCleanSlug(paymentData.metadata.slug);
 
          // Re-consultamos con el token real del negocio para obtener metadata correcta
          const { data: userNegocio } = await supabase
            .from("usuarios")
            .select("mp_access_token, email")
            .eq("slug", slug)
            .single();
 
          let metadataFinal = paymentData.metadata;
          if (userNegocio?.mp_access_token) {
            const real = await fetch(
              `https://api.mercadopago.com/v1/payments/${paymentId}`,
              {
                headers: {
                  Authorization: `Bearer ${userNegocio.mp_access_token}`,
                },
              }
            );
            const realData = await real.json();
            metadataFinal = realData.metadata;
          }
 
          const { nombre, telefono, email, fecha, hora } = metadataFinal;
          const partes = fecha.split("-");
          const textoTurno = `${partes[2]}/${partes[1]} - ${hora}`;
          const fechaHoy = new Date().toLocaleDateString("es-AR", {
            timeZone: "America/Argentina/Buenos_Aires",
          });
 
          const sheets = await getSheets();
          await sheets.spreadsheets.values.append({
            spreadsheetId: MASTER_SHEET_ID,
            range: "A:G",
            valueInputOption: "RAW",
            requestBody: {
              values: [
                [
                  nombre?.trim() || "Cliente",
                  telefono?.toString().trim() || "N/A",
                  textoTurno,
                  fechaHoy,
                  slug,
                  "PENDIENTE",
                  email?.trim() || "",
                ],
              ],
            },
          });
 
          // Notificación por mail al admin y al cliente
          if (userNegocio?.email) {
            try {
              await fetch(APPS_SCRIPT_URL, {
                method: "POST",
                headers: { "Content-Type": "text/plain" },
                body: JSON.stringify({
                  action: "newAppointmentEmail",
                  nombreCliente: nombre?.trim() || "Cliente",
                  fechaHora: textoTurno,
                  adminEmail: userNegocio.email,
                  emailCliente: email?.trim() || "",
                }),
              });
            } catch (mailErr) {
              console.error("Error enviando mail webhook:", mailErr.message);
            }
          }
 
          delete globalCache[slug];
          console.log(`Turno agendado vía pago para: ${slug}`);
        }
      }
    }
 
    res.sendStatus(200);
  } catch (e) {
    console.error("Error en webhook:", e.message);
    res.sendStatus(200);
  }
});
 
// ─── TURNOS ───────────────────────────────────────────────────────────────────
 
// GET /get-occupied?slug=...
// Devuelve los turnos ocupados de un negocio.
app.get("/get-occupied", async (req, res) => {
  try {
    const slug = getCleanSlug(req.query.slug);
    const sheets = await getSheets();
    const response = await sheets.spreadsheets.values.get({
      spreadsheetId: MASTER_SHEET_ID,
      range: "A:F",
    });
    const rows = response.data.values || [];
    const ocupados = rows
      .filter((row) => row[4] === slug)
      .map((row) => row[2]);
    res.json({ success: true, ocupados });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});
 
// POST /create-booking
// Crea un turno gratuito (sin pago). Si el negocio requiere pago, rechaza.
app.post("/create-booking", async (req, res) => {
  try {
    const { name, phone, email, fecha, hora, slug: rawSlug } = req.body;
    const slug = getCleanSlug(rawSlug);
 
    const { data: user, error: userError } = await supabase
      .from("usuarios")
      .select("*")
      .eq("slug", slug)
      .single();
 
    if (userError || !user) {
      return res
        .status(404)
        .json({ success: false, error: "Negocio no encontrado." });
    }
 
    // Bloquear si el negocio requiere pago previo
    const requierePago =
      user.mp_access_token &&
      (user.metodo_pago === "sena" || user.metodo_pago === "total");
    if (requierePago) {
      return res.status(403).json({
        success: false,
        error: "Este turno requiere pago previo.",
      });
    }
 
    const sheets = await getSheets();
 
    // Anti-duplicado: bloquea si ya tiene un turno futuro activo (por tel o email)
    const existingData = await sheets.spreadsheets.values.get({
      spreadsheetId: MASTER_SHEET_ID,
      range: "A:G",
    });
    const existingRows = existingData.data.values || [];
 
    const yaExiste = existingRows.some((row) => {
      const phoneFila = row[1]?.toString().trim();
      const slugFila = row[4]?.toString().toLowerCase().trim();
      const emailFila = row[6]?.toString().toLowerCase().trim();
      const turnoFila = row[2]?.toString().trim();
 
      const mismoSlug = slugFila === slug;
      const mismoTelefono = phoneFila === phone.toString().trim();
      const mismoEmail =
        email && emailFila && emailFila === email.trim().toLowerCase();
 
      if (!mismoSlug || (!mismoTelefono && !mismoEmail)) return false;
      if (!turnoFila || !turnoFila.includes("/")) return false;
 
      const partes = turnoFila.split(" - ");
      if (partes.length < 2) return false;
      const [dia, mes] = partes[0].split("/").map(Number);
      const [hora, minuto] = partes[1].split(":").map(Number);
      const fechaTurno = new Date(
        new Date().getFullYear(),
        mes - 1,
        dia,
        hora,
        minuto
      );
      return fechaTurno > new Date();
    });
 
    if (yaExiste) {
      return res.status(400).json({
        success: false,
        error: "Ya tenés un turno agendado activo.",
      });
    }
 
    // Guardar en Sheets
    const partes = fecha.split("-");
    const textoTurno = `${partes[2]}/${partes[1]} - ${hora}`;
    const fechaHoy = new Date().toLocaleDateString("es-AR", {
      timeZone: "America/Argentina/Buenos_Aires",
    });
 
    await sheets.spreadsheets.values.append({
      spreadsheetId: MASTER_SHEET_ID,
      range: "A:G",
      valueInputOption: "RAW",
      requestBody: {
        values: [
          [
            name.trim(),
            phone.toString().trim(),
            textoTurno,
            fechaHoy,
            slug,
            "PENDIENTE",
            email?.trim() || "",
          ],
        ],
      },
    });
 
    // Notificación por mail
    try {
      await fetch(APPS_SCRIPT_URL, {
        method: "POST",
        headers: { "Content-Type": "text/plain" },
        body: JSON.stringify({
          action: "newAppointmentEmail",
          nombreCliente: name.trim(),
          fechaHora: textoTurno,
          adminEmail: user.email,
          emailCliente: email?.trim() || "",
        }),
      });
    } catch (mailErr) {
      console.error("Error notificando mail:", mailErr.message);
    }
 
    delete globalCache[slug];
    res.json({ success: true });
  } catch (e) {
    console.error("Error en /create-booking:", e.message);
    res.status(500).json({ error: e.message });
  }
});
 
// ─── SLOTS DISPONIBLES ────────────────────────────────────────────────────────
 
// GET /slots-disponibles/:slug?fecha=YYYY-MM-DD&servicio_id=...
// Devuelve los slots del día con cuántos lugares quedan.
app.get("/slots-disponibles/:slug", async (req, res) => {
  try {
    const slug = getCleanSlug(req.params.slug);
    const { fecha, servicio_id } = req.query;
 
    const { data: user, error: userError } = await supabase
      .from("usuarios")
      .select("horarios, duracion_turno, capacidad_por_turno, excepciones")
      .eq("slug", slug)
      .single();
 
    if (userError || !user) {
      return res.status(404).json({ error: "Negocio no encontrado." });
    }
 
    let duracion = user.duracion_turno || 30;
    let capacidad = user.capacidad_por_turno || 1;
 
    if (servicio_id) {
      const { data: servicio } = await supabase
        .from("servicios")
        .select("duracion, capacidad")
        .eq("id", servicio_id)
        .single();
      if (servicio) {
        duracion = servicio.duracion || duracion;
        capacidad = servicio.capacidad || capacidad;
      }
    }
 
    if (user.excepciones?.includes(fecha)) {
      return res.json({ success: true, slots: [] });
    }
 
    const diasSemana = [
      "domingo",
      "lunes",
      "martes",
      "miercoles",
      "jueves",
      "viernes",
      "sabado",
    ];
    const fechaObj = new Date(fecha + "T12:00:00");
    const diaNombre = diasSemana[fechaObj.getDay()];
    const diaConfig = user.horarios?.[diaNombre];
 
    if (!diaConfig?.activo) {
      return res.json({ success: true, slots: [] });
    }
 
    const toMinutes = (t) => {
      if (!t) return null;
      const [h, m] = t.split(":").map(Number);
      return h * 60 + m;
    };
    const fromMinutes = (mins) => {
      const h = Math.floor(mins / 60).toString().padStart(2, "0");
      const m = (mins % 60).toString().padStart(2, "0");
      return `${h}:${m}`;
    };
 
    const [jornadaIni, jornadaFin] = diaConfig.jornada;
    const [descansoIni, descansoFin] = diaConfig.descanso || [null, null];
    const inicio = toMinutes(jornadaIni);
    const fin = toMinutes(jornadaFin);
    const dIni = toMinutes(descansoIni);
    const dFin = toMinutes(descansoFin);
 
    const slotsGenerados = [];
    let cursor = inicio;
    while (cursor + duracion <= fin) {
      const enDescanso = dIni && dFin && cursor >= dIni && cursor < dFin;
      if (!enDescanso) slotsGenerados.push(fromMinutes(cursor));
      cursor += duracion;
    }
 
    const sheets = await getSheets();
    const sheetData = await sheets.spreadsheets.values.get({
      spreadsheetId: MASTER_SHEET_ID,
      range: "A:G",
    });
 
    const allRows = sheetData.data.values || [];
    const [anio, mes, dia] = fecha.split("-");
    const fechaFormateada = `${dia}/${mes}`;
 
    const reservasPorSlot = {};
    allRows.forEach((row, i) => {
      if (i === 0) return;
      const turnoFila = row[2]?.toString().trim();
      const slugFila = row[4]?.toString().toLowerCase().trim();
      if (slugFila !== slug || !turnoFila) return;
      const partes = turnoFila.split(" - ");
      if (partes.length < 2) return;
      if (partes[0].trim() === fechaFormateada) {
        const horaFila = partes[1].trim();
        reservasPorSlot[horaFila] = (reservasPorSlot[horaFila] || 0) + 1;
      }
    });
 
    const slots = slotsGenerados.map((slot) => {
      const reservados = reservasPorSlot[slot] || 0;
      const disponibles = capacidad - reservados;
      return {
        hora: slot,
        disponibles: Math.max(0, disponibles),
        lleno: disponibles <= 0,
      };
    });
 
    res.json({ success: true, slots });
  } catch (e) {
    console.error("Error en /slots-disponibles:", e.message);
    res.status(500).json({ error: e.message });
  }
});
 
// ─── SERVICIOS ────────────────────────────────────────────────────────────────
 
// GET /servicios/:slug — servicios activos (para el público)
app.get("/servicios/:slug", async (req, res) => {
  try {
    const slug = getCleanSlug(req.params.slug);
    const { data, error } = await supabase
      .from("servicios")
      .select("*")
      .eq("slug", slug)
      .eq("activo", true)
      .order("created_at", { ascending: true });
    if (error) throw error;
    res.json({ success: true, servicios: data || [] });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});
 
// GET /servicios/admin/:slug — todos los servicios (para el dashboard)
app.get("/servicios/admin/:slug", async (req, res) => {
  try {
    const slug = getCleanSlug(req.params.slug);
    const { data, error } = await supabase
      .from("servicios")
      .select("*")
      .eq("slug", slug)
      .order("created_at", { ascending: true });
    if (error) throw error;
    res.json({ success: true, servicios: data || [] });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});
 
// POST /servicios/crear
app.post("/servicios/crear", async (req, res) => {
  try {
    const { slug, nombre, descripcion, duracion, precio, capacidad } = req.body;
    const cleanSlug = getCleanSlug(slug);
 
    if (!cleanSlug || !nombre || !duracion || precio === undefined) {
      return res
        .status(400)
        .json({ error: "Faltan campos: slug, nombre, duracion, precio." });
    }
 
    const { data, error } = await supabase
      .from("servicios")
      .insert([
        {
          slug: cleanSlug,
          nombre: nombre.trim(),
          descripcion: descripcion?.trim() || "",
          duracion: parseInt(duracion),
          precio: Number(precio),
          capacidad: parseInt(capacidad) || 1,
          activo: true,
        },
      ])
      .select()
      .single();
 
    if (error) throw error;
    delete globalCache[cleanSlug];
    res.json({ success: true, servicio: data });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});
 
// POST /servicios/editar
app.post("/servicios/editar", async (req, res) => {
  try {
    const { id, slug, nombre, descripcion, duracion, precio, capacidad, activo } =
      req.body;
    const cleanSlug = getCleanSlug(slug);
    if (!id) return res.status(400).json({ error: "Falta el id." });
 
    const updateData = {};
    if (nombre !== undefined) updateData.nombre = nombre.trim();
    if (descripcion !== undefined) updateData.descripcion = descripcion.trim();
    if (duracion !== undefined) updateData.duracion = parseInt(duracion);
    if (precio !== undefined) updateData.precio = Number(precio);
    if (capacidad !== undefined) updateData.capacidad = parseInt(capacidad);
    if (activo !== undefined) updateData.activo = activo;
 
    const { data, error } = await supabase
      .from("servicios")
      .update(updateData)
      .eq("id", id)
      .eq("slug", cleanSlug)
      .select()
      .single();
 
    if (error) throw error;
    delete globalCache[cleanSlug];
    res.json({ success: true, servicio: data });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});
 
// POST /servicios/eliminar
app.post("/servicios/eliminar", async (req, res) => {
  try {
    const { id, slug } = req.body;
    const cleanSlug = getCleanSlug(slug);
    if (!id) return res.status(400).json({ error: "Falta el id." });
 
    const { error } = await supabase
      .from("servicios")
      .delete()
      .eq("id", id)
      .eq("slug", cleanSlug);
 
    if (error) throw error;
    delete globalCache[cleanSlug];
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});
 
// ─── AUTH Y REGISTRO ──────────────────────────────────────────────────────────
 
// POST /api/request-verification
// Paso 1 del registro: envía código de verificación por email vía Apps Script.
app.post("/api/request-verification", async (req, res) => {
  try {
    const { email, business_name, password, precio, duracion_turno, horarios } =
      req.body;
 
    if (!email || !business_name || !password) {
      return res
        .status(400)
        .json({ error: "Faltan datos: email, negocio o contraseña." });
    }
 
    const googleRes = await fetch(APPS_SCRIPT_URL, {
      method: "POST",
      headers: { "Content-Type": "text/plain" },
      body: JSON.stringify({
        action: "sendCode",
        email: email.trim().toLowerCase(),
        usuario: business_name,
        password,
        precio: precio || 0,
        duracion_turno: duracion_turno || 30,
        horarios:
          typeof horarios === "string" ? horarios : JSON.stringify(horarios),
      }),
    });
 
    const text = await googleRes.text();
    const start = text.indexOf("{");
    const end = text.lastIndexOf("}");
    if (start === -1 || end === -1) {
      return res
        .status(500)
        .json({ error: "Respuesta inválida del servidor de correos." });
    }
 
    const result = JSON.parse(text.substring(start, end + 1));
    if (result.status === "success") {
      res.json({ success: true });
    } else {
      res.status(500).json({ error: result.message || "Error en Google Script." });
    }
  } catch (e) {
    console.error("Error en /api/request-verification:", e.message);
    res.status(500).json({ error: "Error de conexión con el servicio de correos." });
  }
});
 
// POST /api/verify-and-register
// Paso 2 del registro: valida el código y crea el usuario en Supabase.
app.post("/api/verify-and-register", async (req, res) => {
  try {
    const {
      email,
      code,
      business_name,
      nombre_persona,
      precio,
      duracion_turno,
      horarios,
      telefono,
    } = req.body;
 
    const googleRes = await fetch(APPS_SCRIPT_URL, {
      method: "POST",
      headers: { "Content-Type": "text/plain" },
      body: JSON.stringify({
        action: "verifyCode",
        email: email.trim().toLowerCase(),
        code: code.toString().trim(),
      }),
    });
 
    const result = await googleRes.json();
 
    if (result.status !== "valid") {
      return res
        .status(400)
        .json({ error: "El código de verificación es incorrecto." });
    }
 
    const finalName = business_name || result.usuario || "Negocio";
    const cleanSlug = getCleanSlug(finalName);
    const magicToken = crypto.randomBytes(16).toString("hex");
 
    const { error } = await supabase.from("usuarios").insert([
      {
        slug: cleanSlug,
        email: email.trim().toLowerCase(),
        nombre_persona: nombre_persona?.trim() || "Dueño",
        business_name: finalName.trim(),
        password: String(result.password),
        sheet_id: MASTER_SHEET_ID,
        precio: parseInt(precio) || 0,
        duracion_turno: parseInt(duracion_turno) || 30,
        horarios: horarios || {},
        telefono: telefono || null,
        metodo_pago: "none",
        excepciones: [],
        mp_access_token: null,
        access_token: magicToken,
      },
    ]);
 
    if (error) {
      if (error.code === "23505") {
        return res.status(400).json({
          error: "El nombre de este negocio ya existe. Intentá con otro.",
        });
      }
      throw error;
    }
 
    // Mail de bienvenida (no bloquea la respuesta si falla)
    fetch(APPS_SCRIPT_URL, {
      method: "POST",
      headers: { "Content-Type": "text/plain" },
      body: JSON.stringify({
        action: "welcomeEmail",
        email: email.trim().toLowerCase(),
        usuario: finalName.trim(),
      }),
    }).catch((e) => console.error("Error mail bienvenida:", e.message));
 
    console.log(`Usuario registrado: ${cleanSlug}`);
    res.json({
      success: true,
      slug: cleanSlug,
      at: magicToken,
      message: "Cuenta creada con éxito.",
    });
  } catch (e) {
    console.error("Error en /api/verify-and-register:", e.message);
    res.status(500).json({ error: "No se pudo completar el registro." });
  }
});
 
// POST /login
// Login con slug + contraseña. Devuelve un magic token de sesión.
app.post("/login", async (req, res) => {
  try {
    const slug = getCleanSlug(req.body.slug);
    const { password } = req.body;
 
    const { data: user, error } = await supabase
      .from("usuarios")
      .select("*")
      .eq("slug", slug)
      .single();
 
    if (error || !user) {
      return res.status(401).json({ success: false, error: "Usuario no encontrado." });
    }
 
    if (String(user.password) !== String(password)) {
      return res.status(401).json({ success: false, error: "Contraseña incorrecta." });
    }
 
    const magicToken = crypto.randomBytes(16).toString("hex");
    await supabase
      .from("usuarios")
      .update({ access_token: magicToken })
      .eq("slug", slug);
 
    res.json({ success: true, slug: user.slug, at: magicToken });
  } catch (e) {
    console.error("Error en /login:", e.message);
    res.status(500).json({ error: e.message });
  }
});
 
// GET /verify-session?u=slug&at=token
// Valida si la sesión es activa. Consume el magic token si se usa.
app.get("/verify-session", async (req, res) => {
  try {
    const slug = getCleanSlug(req.query.u);
    const magicToken = req.query.at;
 
    if (!slug) return res.json({ active: false, reason: "no_slug" });
 
    const { data: user, error } = await supabase
      .from("usuarios")
      .select("slug, access_token, business_name, email")
      .eq("slug", slug)
      .single();
 
    if (error || !user) {
      return res.json({ active: false, reason: "user_not_found" });
    }
 
    // Magic login: consume el token y autentica
    if (magicToken && user.access_token === magicToken) {
      await supabase
        .from("usuarios")
        .update({ access_token: null })
        .eq("slug", slug);
 
      return res.json({
        active: true,
        slug: user.slug,
        business_name: user.business_name,
        email: user.email,
        magicLogin: true,
      });
    }
 
    res.json({
      active: true,
      slug: user.slug,
      business_name: user.business_name,
      email: user.email,
    });
  } catch (e) {
    console.error("Error en /verify-session:", e.message);
    res.status(500).json({ active: false, error: e.message });
  }
});
 
// POST /api/request-password-reset
// Paso 1 reset: envía código al email para cambio de contraseña.
app.post("/api/request-password-reset", async (req, res) => {
  try {
    const { email, newPassword } = req.body;
    if (!email || !newPassword) {
      return res.status(400).json({ error: "Faltan datos." });
    }
 
    const { data: user, error } = await supabase
      .from("usuarios")
      .select("slug")
      .eq("email", email.trim().toLowerCase())
      .single();
 
    if (error || !user) {
      return res
        .status(404)
        .json({ error: "No existe una cuenta con ese correo." });
    }
 
    const googleRes = await fetch(APPS_SCRIPT_URL, {
      method: "POST",
      headers: { "Content-Type": "text/plain" },
      body: JSON.stringify({
        action: "resetPassword",
        email: email.trim().toLowerCase(),
        newPassword,
      }),
    });
 
    const text = await googleRes.text();
    const result = JSON.parse(
      text.substring(text.indexOf("{"), text.lastIndexOf("}") + 1)
    );
    if (result.status === "success") res.json({ success: true });
    else res.status(500).json({ error: result.message });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});
 
// POST /api/verify-and-reset-password
// Paso 2 reset: valida código y actualiza la contraseña en Supabase.
app.post("/api/verify-and-reset-password", async (req, res) => {
  try {
    const { email, code } = req.body;
    const googleRes = await fetch(APPS_SCRIPT_URL, {
      method: "POST",
      headers: { "Content-Type": "text/plain" },
      body: JSON.stringify({
        action: "verifyCode",
        email: email.trim().toLowerCase(),
        code: code.toString().trim(),
      }),
    });
    const result = await googleRes.json();
    if (result.status === "valid") {
      const { error } = await supabase
        .from("usuarios")
        .update({ password: String(result.password) })
        .eq("email", email.trim().toLowerCase());
      if (error) throw error;
      res.json({ success: true });
    } else {
      res.status(400).json({ error: "Código incorrecto o expirado." });
    }
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});
 
// ─── ADMIN Y CONFIG ───────────────────────────────────────────────────────────
 
// GET /admin-stats/:slug
// Devuelve estadísticas del negocio y lista de turnos para el dashboard.
app.get("/admin-stats/:slug", async (req, res) => {
  const slug = getCleanSlug(req.params.slug);
  const now = Date.now();
 
  if (
    globalCache[slug] &&
    now - globalCache[slug].timestamp < CACHE_DURATION
  ) {
    return res.json(globalCache[slug].data);
  }
 
  try {
    const { data: user, error: userError } = await supabase
      .from("usuarios")
      .select("*")
      .eq("slug", slug)
      .single();
 
    if (userError || !user) {
      return res.status(404).json({ error: "Usuario no encontrado." });
    }
 
    const sheets = await getSheets();
    const response = await sheets.spreadsheets.values.get({
      spreadsheetId: MASTER_SHEET_ID,
      range: "A:E",
    });
 
    const allRows = response.data.values || [];
    const rows = allRows.filter(
      (r, i) => i === 0 || (r[4] && getCleanSlug(r[4]) === slug)
    );
 
    const ahoraArg = new Date(
      new Date().toLocaleString("en-US", {
        timeZone: "America/Argentina/Buenos_Aires",
      })
    );
    const mesActual = ahoraArg.getMonth() + 1;
    const diaHoyNum = ahoraArg.getDate();
    const anioActual = ahoraArg.getFullYear();
 
    let turnosHoy = 0;
    let turnosMesActual = 0;
    let turnosLista = [];
    const semanas = { "Sem 1": 0, "Sem 2": 0, "Sem 3": 0, "Sem 4": 0 };
 
    rows.forEach((r, i) => {
      if (i === 0 || !r[2]) return;
      const partes = r[2].toString().split(" - ");
      if (partes.length < 2) return;
      const [dia, mes] = partes[0].split("/").map(Number);
 
      let semanaIdx = 0;
      if (dia > 7 && dia <= 14) semanaIdx = 1;
      else if (dia > 14 && dia <= 21) semanaIdx = 2;
      else if (dia > 21) semanaIdx = 3;
 
      if (mes === mesActual) {
        turnosMesActual++;
        if (dia === diaHoyNum) turnosHoy++;
        semanas[`Sem ${semanaIdx + 1}`]++;
      }
 
      turnosLista.push({
        nombre: r[0],
        telefono: r[1],
        fecha: `${anioActual}-${String(mes).padStart(2, "0")}-${String(dia).padStart(2, "0")}`,
        hora: partes[1],
        semanaIdx,
        duracion: user.duracion_turno || 60,
        rawTurno: r[2],
      });
    });
 
    const finalData = {
      stats: {
        nombre_persona: user.nombre_persona,
        turnosHoy,
        turnosMes: turnosMesActual,
        ingresosEstimados: turnosMesActual * (user.precio || 0),
        promedioDiario:
          diaHoyNum > 0
            ? Math.round(
                (turnosMesActual * (user.precio || 0)) / diaHoyNum
              )
            : 0,
        chartData: Object.keys(semanas).map((key) => ({
          label: key,
          turnos: semanas[key],
        })),
        businessName: user.business_name,
        horarios: user.horarios,
        config: {
          duracion: user.duracion_turno,
          precio: user.precio,
          monto_sena: user.monto_sena || 0,
          metodo_pago: user.metodo_pago || "none",
          mp_status: user.mp_access_token ? "Conectado" : "Desconectado",
          excepciones: user.excepciones || [],
        },
        turnosLista: turnosLista.reverse(),
      },
    };
 
    globalCache[slug] = { timestamp: now, data: finalData };
    res.json(finalData);
  } catch (e) {
    console.error("Error en /admin-stats:", e.message);
    res.status(500).json({ error: "Error al procesar las estadísticas." });
  }
});
 
// POST /update-settings
// Actualiza precio, horarios, duración y método de pago del negocio.
app.post("/update-settings", async (req, res) => {
  try {
    const {
      slug,
      precio,
      horarios,
      duracion_turno,
      ocupados,
      monto_sena,
      metodo_pago,
    } = req.body;
    const cleanSlug = getCleanSlug(slug);
 
    const numPrecio = parseInt(precio) || 0;
    const numSena = parseInt(monto_sena) || 0;
 
    const updateData = {
      precio: numPrecio,
      monto_sena: numSena,
      metodo_pago: metodo_pago || "none",
      duracion_turno: parseInt(duracion_turno) || 30,
    };
 
    if (horarios) updateData.horarios = horarios;
    if (ocupados) updateData.excepciones = ocupados;
 
    const { error } = await supabase
      .from("usuarios")
      .update(updateData)
      .eq("slug", cleanSlug);
 
    if (error) throw error;
    delete globalCache[cleanSlug];
    res.json({ success: true });
  } catch (e) {
    console.error("Error en /update-settings:", e.message);
    res.status(500).json({ error: e.message });
  }
});
 
// POST /cancel-appointment
// Elimina una fila de Sheets (cancela un turno).
app.post("/cancel-appointment", async (req, res) => {
  try {
    const { slug, rawTurno } = req.body;
    const cleanSlug = getCleanSlug(slug);
 
    const sheets = await getSheets();
    const response = await sheets.spreadsheets.values.get({
      spreadsheetId: MASTER_SHEET_ID,
      range: "A:E",
    });
 
    const rows = response.data.values || [];
    const rowIndex = rows.findIndex(
      (r) => r[2] === rawTurno && r[4] === cleanSlug
    );
 
    if (rowIndex === -1) {
      return res.status(404).json({ error: "Turno no encontrado." });
    }
 
    const spreadsheet = await sheets.spreadsheets.get({
      spreadsheetId: MASTER_SHEET_ID,
    });
    const sheetIdReal =
      spreadsheet.data.sheets[0].properties.sheetId;
 
    await sheets.spreadsheets.batchUpdate({
      spreadsheetId: MASTER_SHEET_ID,
      requestBody: {
        requests: [
          {
            deleteDimension: {
              range: {
                sheetId: sheetIdReal,
                dimension: "ROWS",
                startIndex: rowIndex,
                endIndex: rowIndex + 1,
              },
            },
          },
        ],
      },
    });
 
    delete globalCache[cleanSlug];
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});
 
// ─── ARRANQUE ─────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 10000;
app.listen(PORT, () =>
  console.log(`NegoSocio API corriendo en puerto ${PORT}`)
);
 
