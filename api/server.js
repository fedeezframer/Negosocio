import express from "express";
import cors from "cors";
import { createClient } from '@supabase/supabase-js';
import { google } from "googleapis";
import { MercadoPagoConfig, Preference } from "mercadopago";
import fetch from "node-fetch";
import crypto from "crypto";

const app = express();

// --- CONFIGURACIÓN GLOBAL ---
const MASTER_SHEET_ID = "1CYF1IJFEKibbkXTKco-o13ZbMo6KpkT5oJj35Z3q4hg";
const APPS_SCRIPT_URL = "https://script.google.com/macros/s/AKfycbzvcaYhHuyD-Xu63Aw9WpWrpcr5xmrgHW_IffXkmC90bs0pTzhWP1d8rWBaBuhG5Icx/exec";
const registrosTemporales = {};

app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);

// --- CACHÉ SISTEMA ---
const globalCache = {};
const CACHE_DURATION = 20000;

const getCleanSlug = (rawSlug) => {
    if (!rawSlug) return "";
    return rawSlug
        .toLowerCase()
        .trim()
        .normalize("NFD")
        .replace(/[\u0300-\u036f]/g, "")
        .replace(/\s+/g, '-')
        .replace(/[^a-z0-9-]/g, '');
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

// --- LÓGICA DE TOKENS ---
async function handleTokenDiscount(slug) {
    try {
        const { data: user, error: userError } = await supabase
            .from('usuarios')
            .select('plan, tokens')
            .eq('slug', slug)
            .single();

        if (userError || !user) return;

        // Si es premium, no descontamos (tiene 100k tokens de base)
        if (user.plan === 'premium') return;

        // Si es gratis, bajamos 1
        if (user.tokens > 0) {
            await supabase
                .from('usuarios')
                .update({ tokens: user.tokens - 1 })
                .eq('slug', slug);
        }
    } catch (e) {
        console.error("Error al descontar token:", e.message);
    }
}

// --- RUTAS DE SISTEMA ---
app.get("/", (req, res) => {
    res.send("🚀 NegoSocio API Server Is Online (Full Mode)");
});

// --- MERCADO PAGO: PREFERENCIA ---
app.post("/api/create-preference", async (req, res) => {
    try {
        const { nombre, telefono, email, fecha, hora, slug } = req.body;
        const cleanSlug = getCleanSlug(slug);
        const { data: user, error: userError } = await supabase
            .from('usuarios')
            .select('*')
            .eq('slug', cleanSlug)
            .single();
        if (userError || !user) {
            return res.status(404).json({ error: "Negocio no encontrado." });
        }
        // --- BLOQUEO POR VENCIMIENTO PREMIUM ---
        if (user.plan === 'premium') {
            const ahora = new Date();
            const vencimiento = user.subscription_expiry ? new Date(user.subscription_expiry) : null;
            if (!vencimiento || ahora > vencimiento) {
                return res.status(403).json({ 
                    error: "Servicio suspendido", 
                    message: "Este negocio tiene las reservas pausadas temporalmente." 
                });
            }
        }
        let precioReal = 0;
        let conceptoPago = "Total";
        if (user.metodo_pago === 'sena') {
            precioReal = Number(user.monto_sena) || 0;
            conceptoPago = "Seña";
        } else {
            precioReal = Number(user.precio) || 0;
            conceptoPago = "Total";
        }
        if (precioReal <= 0) return res.json({ isFree: true });
        if (!user.mp_access_token) {
            return res.status(400).json({ error: "Este negocio no configuró Mercado Pago." });
        }
        const clientMP = new MercadoPagoConfig({ accessToken: user.mp_access_token });
        const preference = new Preference(clientMP);
        const response = await preference.create({
            body: {
                items: [{
                    title: `Reserva ${conceptoPago}: ${fecha} - ${hora}hs`,
                    unit_price: precioReal,
                    quantity: 1,
                    currency_id: "ARS"
                }],
                metadata: { 
                    nombre: nombre,
                    telefono: telefono,
                    email: email || "",
                    fecha: fecha,
                    hora: hora,
                    slug: cleanSlug,
                    tipo_pago: user.metodo_pago || 'total'
                },
                notification_url: "https://framerturnero.onrender.com/webhook",
                back_urls: { 
                    success: "https://negosocio.framer.website/success",
                    failure: "https://negosocio.framer.website/dashboard",
                    pending: "https://negosocio.framer.website/dashboard"
                },
                auto_return: "approved"
            },
        });
        res.json({ payment_url: response.init_point });
    } catch (error) {
        console.error("Error en create-preference:", error.message);
        res.status(500).json({ error: error.message });
    }
});

// --- MERCADO PAGO: OAUTH ---
app.get("/oauth-callback", async (req, res) => {
    const { code, state: slug } = req.query;
    
    // Verificación básica de seguridad: nos aseguramos de tener el código de MP y el slug del usuario
    if (!code || !slug) {
        console.error("Callback fallido: Faltan parámetros code o slug.");
        return res.status(400).send("Datos inválidos.");
    }

    try {
        // Intercambiamos el code temporal por el access_token definitivo del cliente
        const response = await fetch("https://api.mercadopago.com/oauth/token", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                client_id: process.env.MP_TURNERO_CLIENT_ID, // Tu Client ID de la aplicación en MP
                client_secret: process.env.MP_TURNERO_CLIENT_SECRET, // Tu Client Secret de la aplicación en MP
                grant_type: "authorization_code",
                code: code,
                redirect_uri: "https://framerturnero.onrender.com/oauth-callback"
            })
        });

        const data = await response.json();

        if (data.access_token) {
            // Guardamos el token de Mercado Pago del cliente en Supabase.
            // Se eliminó 'mp_status' para evitar el error PGRST204 de columna inexistente.
            const { error: supabaseError } = await supabase
                .from('usuarios')
                .update({ 
                    mp_access_token: data.access_token 
                })
                .eq('slug', slug);

            if (supabaseError) {
                console.error("Error al guardar en Supabase:", supabaseError);
                // Si falla el guardado, redirigimos manteniendo el parámetro 'u' para no romper el dashboard
                return res.redirect(`https://negosocio.framer.website/dashboard?status=mp_error&u=${slug}`);
            }

            // Éxito: Redirigimos al dashboard indicando éxito y pasando el slug en el parámetro 'u'
            // Esto permite que PlanGuardian reconozca al usuario y valide su plan correctamente.
            console.log(`✅ Cuenta de Mercado Pago vinculada con éxito para el negocio: ${slug}`);
            res.redirect(`https://negosocio.framer.website/dashboard?status=mp_success&u=${slug}`);
        } else {
            // Si Mercado Pago devuelve un error (ej: code vencido), redirigimos manteniendo el slug si existe
            console.error("Error de Mercado Pago OAuth:", data);
            const errorUrl = slug 
                ? `https://negosocio.framer.website/dashboard?status=mp_error&u=${slug}`
                : `https://negosocio.framer.website/dashboard?status=mp_error`;
            res.redirect(errorUrl);
        }
    } catch (error) {
        // Captura de errores de red o errores críticos de ejecución
        console.error("Error crítico en el flujo OAuth:", error);
        res.status(500).send("Error interno al intentar vincular la cuenta.");
    }
});

app.post("/webhook", async (req, res) => {
    const { query, body } = req;
    
    try {
        console.log(`📩 Webhook recibido. Tipo: ${body.type || query.topic}`);
 
        // --- A. LÓGICA PARA PAGOS DE TURNOS INDIVIDUALES (SEÑAS/TOTALES) ---
        if (query.topic === "payment" || body.type === "payment") {
            const paymentId = query.id || body.data?.id;
            
            if (paymentId) {
                // Primera consulta con token global para obtener el slug del metadata
                const paymentResponse = await fetch(`https://api.mercadopago.com/v1/payments/${paymentId}`, {
                    headers: { Authorization: `Bearer ${process.env.MP_ACCESS_TOKEN}` }
                });
                const paymentData = await paymentResponse.json();

                console.log("🔍 METADATA PRIMERA CONSULTA:", JSON.stringify(paymentData.metadata));
 
                if (paymentData.status === "approved" && paymentData.metadata && paymentData.metadata.slug) {
                    const rawSlug = paymentData.metadata.slug;
                    const slug = rawSlug.toLowerCase().trim().replace(/\s+/g, '-').replace(/[^a-z0-9-]/g, '');

                    // ✅ Buscamos el token real del negocio en Supabase
                    const { data: userNegocio } = await supabase
                        .from('usuarios')
                        .select('mp_access_token')
                        .eq('slug', slug)
                        .single();

                    // ✅ Re-consultamos el pago con el token correcto del negocio
                    let metadataFinal = paymentData.metadata;
                    if (userNegocio && userNegocio.mp_access_token) {
                        const paymentResponseReal = await fetch(`https://api.mercadopago.com/v1/payments/${paymentId}`, {
                            headers: { Authorization: `Bearer ${userNegocio.mp_access_token}` }
                        });
                        const paymentDataReal = await paymentResponseReal.json();
                        console.log("🔍 METADATA CON TOKEN DEL NEGOCIO:", JSON.stringify(paymentDataReal.metadata));
                        metadataFinal = paymentDataReal.metadata;
                    }

                    const { nombre, telefono, email, fecha, hora } = metadataFinal;
                    
                    const partes = fecha.split("-");
                    const textoTurnoNuevo = `${partes[2]}/${partes[1]} - ${hora}`;
                    const fechaHoyReal = new Date().toLocaleDateString('es-AR', { timeZone: 'America/Argentina/Buenos_Aires' });
 
                    const sheets = await getSheets();
                    
                    await sheets.spreadsheets.values.append({
                        spreadsheetId: MASTER_SHEET_ID,
                        range: "A:G",
                        valueInputOption: "RAW",
                        requestBody: { 
                            values: [[
                                nombre ? nombre.trim() : "Cliente",
                                telefono ? telefono.toString().trim() : "N/A",
                                textoTurnoNuevo,
                                fechaHoyReal,
                                slug,
                                "PENDIENTE",
                                email ? email.trim() : ""
                            ]] 
                        }
                    });
 
                    try {
                        const { data: userAdmin } = await supabase
                            .from('usuarios')
                            .select('email')
                            .eq('slug', slug)
                            .single();
 
                        if (userAdmin && userAdmin.email) {
                            await fetch(APPS_SCRIPT_URL, {
                                method: "POST",
                                headers: { "Content-Type": "text/plain" },
                                body: JSON.stringify({
                                    action: "newAppointmentEmail",
                                    nombreCliente: nombre ? nombre.trim() : "Cliente",
                                    fechaHora: textoTurnoNuevo,
                                    adminEmail: userAdmin.email,
                                    emailCliente: email ? email.trim() : ""
                                })
                            });
                            console.log(`📧 Notificación enviada al admin: ${userAdmin.email}`);
                            if (email) {
                                console.log(`📧 Confirmación enviada al cliente: ${email}`);
                            }
                        }
                    } catch (mailErr) {
                        console.error("⚠️ Error al intentar disparar el mail del webhook:", mailErr.message);
                    }
 
                    if (typeof handleTokenDiscount === 'function') {
                        await handleTokenDiscount(slug);
                    }
                    
                    delete globalCache[slug];
                    console.log(`✅ Turno pagado y agendado exitosamente para: ${slug}`);
 
                } else {
                    console.log("ℹ️ Pago recibido sin metadata de turno. Se ignora (posible cobro de suscripción).");
                }
            }
        }
 
        // --- B. LÓGICA PARA SUSCRIPCIÓN PREMIUM (ACTIVACIÓN POR SLUG) ---
        if (body.type === "subscription_preapproval" || body.type === "subscription_authorized_payment") {
            const subId = body.data?.id || body.id;
            
            if (subId) {
                const response = await fetch(`https://api.mercadopago.com/preapproval/${subId}`, {
                    headers: { Authorization: `Bearer ${process.env.MP_ACCESS_TOKEN}` }
                });
                const subData = await response.json();
 
                console.log("🔍 Detalles de suscripción recuperados:", JSON.stringify(subData));
 
                if (subData.status === "authorized" || subData.status === "active") {
                    
                    let slugParaActivar = subData.external_reference;
 
                    if (!slugParaActivar && subData.back_url) {
                        const urlParams = new URLSearchParams(subData.back_url.split('?')[1]);
                        slugParaActivar = urlParams.get('u');
                    }
                    
                    if (!slugParaActivar) {
                        console.error("❌ Error: No se pudo obtener el slug del negocio.");
                        return res.sendStatus(200); 
                    }
 
                    console.log(`🚀 Activando Plan Premium para el slug: ${slugParaActivar}`);
 
                    const vencimiento = new Date();
                    vencimiento.setMonth(vencimiento.getMonth() + 1);
                    vencimiento.setDate(vencimiento.getDate() + 2);
 
                    const { data, error: updateError } = await supabase
                        .from('usuarios')
                        .update({
                            plan: 'premium',
                            tokens: 100000, 
                            subscription_expiry: vencimiento.toISOString(),
                        })
                        .eq('slug', slugParaActivar)
                        .select();
 
                    if (updateError) {
                        console.error("❌ Error al activar premium en Supabase:", updateError.message);
                    } else if (data && data.length > 0) {
                        console.log(`✨ ¡CUENTA ACTIVADA! El negocio ${data[0].business_name} ya es Premium.`);
                        delete globalCache[slugParaActivar];
                    }
 
                    const rawEmail = subData.payer_email || (subData.payer && subData.payer.email);
                    if (rawEmail && typeof registrosTemporales !== 'undefined') {
                        delete registrosTemporales[rawEmail.toLowerCase().trim()];
                    }
                }
            }
        }
 
        res.sendStatus(200);
 
    } catch (e) {
        console.error("🔥 Error crítico en el Webhook:", e.message);
        res.sendStatus(200);
    }
});

app.post("/api/pre-register-premium", async (req, res) => {
    // 1. Recibimos todos los datos desde el DataGuardian de Framer
    const { 
        email, 
        business_name, 
        nombre_persona, 
        precio, 
        duracion_turno, 
        horarios, 
        telefono, 
        plan,
        password 
    } = req.body;
    
    // Validación de seguridad básica: No permitimos registros sin los pilares fundamentales
    if (!email || !business_name || !password) {
        return res.status(400).json({ error: "Faltan datos obligatorios para iniciar el registro." });
    }

    const emailKey = email.trim().toLowerCase();

    try {
        console.log(`🆕 Iniciando pre-registro Premium para: ${emailKey}`);

        // 2. Generación del Slug (URL amigable y único identificador del negocio)
        // Eliminamos acentos, caracteres especiales y convertimos espacios en guiones
        const realSlug = (business_name || "mi-negocio")
            .toLowerCase()
            .trim()
            .normalize("NFD")
            .replace(/[\u0300-\u036f]/g, "") // Quita acentos
            .replace(/\s+/g, '-')             // Espacios por guiones
            .replace(/[^a-z0-9-]/g, '');      // Quita caracteres especiales (deja solo a-z, 0-9 y -)

        // 3. PERSISTENCIA DIRECTA EN SUPABASE
        // Insertamos al usuario con estado 'pendiente'.
        // Usamos 'upsert' con 'onConflict: email' para que si el usuario reintenta, 
        // se actualicen sus preferencias sin crear un duplicado roto.
        const { error: upsertError } = await supabase
            .from('usuarios')
            .upsert({
                email: emailKey,
                slug: realSlug,
                business_name: business_name.trim(),
                nombre_persona: nombre_persona ? nombre_persona.trim() : null,
                password: String(password), 
                precio: parseInt(precio) || 0,
                duracion_turno: parseInt(duracion_turno) || 30,
                horarios: horarios || {},
                telefono: telefono || null,
                plan: 'pendiente', // <--- Se activará a 'premium' mediante el Webhook tras el pago
                tokens: 0,         // El plan premium otorga tokens ilimitados (lógica en Webhook)
                sheet_id: MASTER_SHEET_ID,
                created_at: new Date().toISOString()
            }, { onConflict: 'email' });

        if (upsertError) {
            console.error("❌ Error al guardar en Supabase durante pre-registro:", upsertError.message);
            throw new Error("No se pudo guardar la información del negocio en la base de datos.");
        }

        // 4. LOG DE AUDITORÍA EN GOOGLE SHEETS (Opcional/Respaldo)
        // Registramos el intento en una hoja separada para control administrativo
        try {
            const sheets = await getSheets();
            const fechaHoy = new Date().toLocaleString('es-AR', { timeZone: 'America/Argentina/Buenos_Aires' });
            
            await sheets.spreadsheets.values.append({
                spreadsheetId: MASTER_SHEET_ID,
                range: "Premium Temp!A:C",
                valueInputOption: "RAW",
                requestBody: { 
                    values: [[emailKey, `Registro iniciado para: ${business_name}`, fechaHoy]] 
                }
            });
        } catch (sheetError) {
            // No bloqueamos el proceso si falla Sheets, ya que Supabase es nuestra fuente de verdad
            console.warn("⚠️ No se pudo guardar el log en Sheets, pero el registro en Supabase fue exitoso.");
        }

        console.log(`✅ Pre-registro completado en DB para: ${emailKey} con slug: ${realSlug}`);

        // 5. Respuesta exitosa al frontend para disparar el flujo de Mercado Pago
        res.json({ 
            success: true, 
            message: "Datos de negocio guardados correctamente.",
            slug: realSlug
        });

    } catch (e) {
        console.error("🔥 Error crítico en pre-register-premium:", e.message);
        res.status(500).json({ 
            error: "Error interno al procesar el pre-registro del negocio.",
            details: e.message 
        });
    }
});

app.post("/api/create-subscription", async (req, res) => {
    try {
        const { email } = req.body;

        // Validación de entrada
        if (!email) {
            console.error("⚠️ Intento de suscripción sin email.");
            return res.status(400).json({ 
                error: "El email es obligatorio para generar la suscripción." 
            });
        }

        const userEmailLimpio = email.toLowerCase().trim();

        // 1. Buscamos al usuario en Supabase para obtener su slug real
        // Esto asegura que la suscripción se vincule al negocio correcto
        const { data: user, error: userError } = await supabase
            .from('usuarios')
            .select('slug')
            .eq('email', userEmailLimpio)
            .single();

        if (userError || !user) {
            console.error(`❌ Error: Usuario no encontrado para el email: ${userEmailLimpio}`);
            return res.status(404).json({ error: "Usuario no encontrado. Primero debe completar el registro." });
        }

        const userSlug = user.slug;

        // 2. Generamos un Magic Token aleatorio y seguro para el Login Automático
        const magicToken = crypto.randomBytes(16).toString('hex');

        // 3. PERSISTENCIA EN SUPABASE
        // Guardamos el token en la columna 'access_token' para validarlo al volver del pago
        const { error: updateError } = await supabase
            .from('usuarios')
            .update({ access_token: magicToken })
            .eq('email', userEmailLimpio);

        if (updateError) {
            console.error("❌ Error al guardar magic token en Supabase:", updateError.message);
            throw new Error("No se pudo vincular el token de acceso a la cuenta.");
        }

        console.log(`🔑 Magic Token vinculado en DB para: ${userEmailLimpio}`);

        // 4. Llamada a la API de Mercado Pago para crear la suscripción (Preapproval)
        // Agregamos external_reference para identificar al usuario por SLUG en el Webhook
        const response = await fetch("https://api.mercadopago.com/preapproval", {
            method: "POST",
            headers: {
                "Authorization": `Bearer ${process.env.MP_ACCESS_TOKEN}`,
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                reason: "Plan Premium NegoSocio",
                payer_email: userEmailLimpio,
                // --- MEJORA CLAVE: Vinculamos el slug directamente ---
                external_reference: userSlug, 
                auto_recurring: {
                    frequency: 1,
                    frequency_type: "months",
                    transaction_amount: 18000, // Ajustar al valor real en pesos argentinos
                    currency_id: "ARS"
                },
                // La back_url redirige al Dashboard de Framer con los parámetros de sesión
                back_url: `https://negosocio.framer.website/dashboard?u=${userSlug}&at=${magicToken}`,
                status: "pending"
            })
        });

        const subscription = await response.json();

        // Manejo de errores específicos de la API de Mercado Pago
        if (!response.ok) {
            console.error("❌ Error de MP al generar suscripción:", JSON.stringify(subscription, null, 2));
            return res.status(response.status).json({ 
                error: subscription.message || "No se pudo conectar con Mercado Pago.",
                details: subscription.cause || []
            });
        }

        // Obtenemos el link de pago oficial (init_point)
        const checkoutUrl = subscription.init_point || subscription.sandbox_init_point;

        if (!checkoutUrl) {
            console.error("❌ No se recibió init_point de MP:", subscription);
            throw new Error("No se encontró la URL de pago en la respuesta de Mercado Pago.");
        }

        console.log(`🔗 Link de suscripción Premium generado para: ${userEmailLimpio} (Slug: ${userSlug})`);
        
        // Enviamos la URL al frontend para la redirección
        res.json({ 
            success: true,
            init_point: checkoutUrl,
            message: "Link de suscripción generado correctamente.",
            slug: userSlug
        }); 

    } catch (e) {
        console.error("❌ Error crítico creando suscripción:", e.message);
        res.status(500).json({ 
            error: "Error interno al procesar la suscripción.",
            message: e.message 
        });
    }
});

app.all("/api/system/refresh-tokens", async (req, res) => {
    try {
        // 🔐 Seguridad con API KEY
        const apiKey = req.headers["x-api-key"]
        if (!apiKey || apiKey !== process.env.CRON_SECRET) {
            return res.status(401).json({ error: "Unauthorized" })
        }

        const now = new Date()

        const { data: users, error } = await supabase
            .from("usuarios")
            .select("*")

        if (error) throw error

        let updatedCount = 0

        for (const user of users) {
            // --- GRATIS: recarga mensual ---
            if (user.plan === "gratis") {
                let last = null

                try {
                    last = user.last_token_refresh
                        ? new Date(user.last_token_refresh)
                        : null
                } catch (e) {
                    last = null
                }

                const diffDays = last
                    ? (now - last) / (1000 * 60 * 60 * 24)
                    : 999 // fuerza recarga si nunca tuvo

                if (diffDays >= 30) {
                    const newTokens = (user.tokens || 0) + 25

                    await supabase
                        .from("usuarios")
                        .update({
                            tokens: newTokens,
                            last_token_refresh: now.toISOString()
                        })
                        .eq("id", user.id)

                    console.log(
                        `🔄 Tokens sumados: ${user.slug} → ${user.tokens} + 25 = ${newTokens}`
                    )

                    updatedCount++
                }
            }

            // --- PREMIUM: expiración ---
            if (user.plan === "premium") {
                let expiry = null

                try {
                    expiry = user.subscription_expiry
                        ? new Date(user.subscription_expiry)
                        : null
                } catch (e) {
                    expiry = null
                }

                if (!expiry || now > expiry) {
                    await supabase
                        .from("usuarios")
                        .update({
                            plan: "gratis",
                            tokens: 25,
                            last_token_refresh: now.toISOString()
                        })
                        .eq("id", user.id)

                    console.log(`⬇️ Usuario degradado: ${user.slug}`)

                    updatedCount++
                }
            }
        }

        res.json({
            success: true,
            message: `Proceso completado`,
            usersUpdated: updatedCount
        })
    } catch (e) {
        console.error("❌ Error sistema tokens:", e.message)
        res.status(500).json({ error: "Error sistema tokens" })
    }
})

// --- GESTIÓN DE TURNOS ---
app.get("/get-occupied", async (req, res) => {
    try {
        const slug = getCleanSlug(req.query.slug);
        const sheets = await getSheets();
        // Traemos hasta la F para asegurar que leemos toda la fila si fuera necesario
        const response = await sheets.spreadsheets.values.get({ 
            spreadsheetId: MASTER_SHEET_ID, 
            range: "A:F" 
        });
        const rows = response.data.values || [];
        // Filtramos por slug (columna E index 4) y devolvemos el turno (columna C index 2)
        const ocupados = rows.filter(row => row[4] === slug).map(row => row[2]);
        res.json({ success: true, ocupados });
    } catch (e) { 
        res.status(500).json({ error: e.message }); 
    }
});

app.post("/create-booking", async (req, res) => {
    try {
        const { name, phone, email, fecha, hora, slug: rawSlug } = req.body;
        const slug = getCleanSlug(rawSlug);
 
        const { data: user, error: userError } = await supabase
            .from('usuarios')
            .select('*')
            .eq('slug', slug)
            .single();
 
        if (userError || !user) {
            return res.status(404).json({ success: false, error: "Negocio no encontrado." });
        }
 
        // --- 🔒 BLOQUEO SI REQUIERE PAGO ---
        const requierePago = user.mp_access_token && (user.metodo_pago === "sena" || user.metodo_pago === "total");
        if (requierePago) {
            return res.status(403).json({
                success: false,
                error: "Este turno requiere pago previo. Debes completar el pago antes de reservar."
            });
        }
 
        // --- Verificación de Plan y Tokens ---
        if (user.plan === 'premium') {
            const ahoraArg = new Date(new Date().toLocaleString("en-US", { timeZone: "America/Argentina/Buenos_Aires" }));
            const vencimiento = user.subscription_expiry ? new Date(user.subscription_expiry) : null;
            if (!vencimiento || ahoraArg > vencimiento) {
                return res.status(403).json({
                    success: false,
                    error: "Servicio suspendido temporalmente."
                });
            }
        }
 
        if (user.plan === 'gratis' && user.tokens <= 0) {
            return res.status(403).json({
                success: false,
                error: "Sin tokens disponibles."
            });
        }
 
        const sheets = await getSheets();
 
        // --- ✅ VALIDACIÓN ANTI-DUPLICADO ---
        // Bloquea si ya existe un turno con el mismo teléfono O el mismo email
        // bajo el mismo slug. El nombre se ignora porque pueden haber homónimos.
        const existingData = await sheets.spreadsheets.values.get({
            spreadsheetId: MASTER_SHEET_ID,
            range: "A:G"
        });
 
        const existingRows = existingData.data.values || [];
 
const yaExiste = existingRows.some(row => {
    const phoneFila = row[1]?.toString().trim()
    const slugFila  = row[4]?.toString().toLowerCase().trim()
    const emailFila = row[6]?.toString().toLowerCase().trim()
    const turnoFila = row[2]?.toString().trim() // "22/04 - 10:00"

    const mismoSlug     = slugFila === slug
    const mismoTelefono = phoneFila === phone.toString().trim()
    const mismoEmail    = email && emailFila && emailFila === email.trim().toLowerCase()

    if (!mismoSlug || (!mismoTelefono && !mismoEmail)) return false

    // Parseamos la fecha del turno para ver si ya pasó
    if (!turnoFila || !turnoFila.includes("/")) return false
    const partes = turnoFila.split(" - ")
    if (partes.length < 2) return false
    const [dia, mes] = partes[0].split("/").map(Number)
    const [hora, minuto] = partes[1].split(":").map(Number)
    const anioActual = new Date().getFullYear()
    const fechaTurno = new Date(anioActual, mes - 1, dia, hora, minuto)
    const ahora = new Date()

    // Solo bloquea si el turno todavía no ocurrió
    return fechaTurno > ahora
})
 
        if (yaExiste) {
            return res.status(400).json({
                success: false,
                error: "Ya tenés un turno agendado. Solo podés tener un turno activo a la vez."
            });
        }
 
        // --- 1. GUARDAR EN GOOGLE SHEETS ---
        const partes = fecha.split("-");
        const textoTurnoNuevo = `${partes[2]}/${partes[1]} - ${hora}`;
        const fechaHoyReal = new Date().toLocaleDateString('es-AR', { timeZone: 'America/Argentina/Buenos_Aires' });
 
        await sheets.spreadsheets.values.append({
            spreadsheetId: MASTER_SHEET_ID,
            range: "A:G",
            valueInputOption: "RAW",
            requestBody: {
                values: [[
                    name.trim(),                      // A
                    phone.toString().trim(),          // B
                    textoTurnoNuevo,                  // C
                    fechaHoyReal,                     // D (fecha de reserva)
                    slug,                             // E
                    "PENDIENTE",                      // F (estado)
                    email ? email.trim() : ""         // G (email del cliente)
                ]]
            }
        });
 
        // --- 2. DISPARAR EL MAIL (Apps Script) ---
        try {
            await fetch(APPS_SCRIPT_URL, {
                method: "POST",
                headers: { "Content-Type": "text/plain" },
                body: JSON.stringify({
                    action: "newAppointmentEmail",
                    nombreCliente: name.trim(),
                    fechaHora: textoTurnoNuevo,
                    adminEmail: user.email,
                    emailCliente: email ? email.trim() : ""
                })
            });
        } catch (mailErr) {
            console.error("Error notificando al Apps Script:", mailErr.message);
        }
 
        await handleTokenDiscount(slug);
        delete globalCache[slug];
 
        res.json({ success: true });
 
    } catch (e) {
        console.error("Error en create-booking:", e.message);
        res.status(500).json({ error: e.message });
    }
});

// ==========================================================
// --- SERVICIOS ---
// ==========================================================

// GET /servicios/:slug — obtener todos los servicios de un negocio
app.get("/servicios/:slug", async (req, res) => {
    try {
        const slug = getCleanSlug(req.params.slug);

        const { data: servicios, error } = await supabase
            .from("servicios")
            .select("*")
            .eq("slug", slug)
            .eq("activo", true)
            .order("created_at", { ascending: true });

        if (error) throw error;

        res.json({ success: true, servicios: servicios || [] });
    } catch (e) {
        console.error("Error en GET /servicios:", e.message);
        res.status(500).json({ error: e.message });
    }
});

// GET /servicios/admin/:slug — obtener TODOS los servicios (activos e inactivos) para el panel
app.get("/servicios/admin/:slug", async (req, res) => {
    try {
        const slug = getCleanSlug(req.params.slug);

        const { data: servicios, error } = await supabase
            .from("servicios")
            .select("*")
            .eq("slug", slug)
            .order("created_at", { ascending: true });

        if (error) throw error;

        res.json({ success: true, servicios: servicios || [] });
    } catch (e) {
        console.error("Error en GET /servicios/admin:", e.message);
        res.status(500).json({ error: e.message });
    }
});

// POST /servicios/crear — crear un nuevo servicio
app.post("/servicios/crear", async (req, res) => {
    try {
        const { slug, nombre, descripcion, duracion, precio, capacidad } = req.body;
        const cleanSlug = getCleanSlug(slug);

        if (!cleanSlug || !nombre || !duracion || precio === undefined) {
            return res.status(400).json({ error: "Faltan campos obligatorios: slug, nombre, duracion, precio." });
        }

        const { data, error } = await supabase
            .from("servicios")
            .insert([{
                slug: cleanSlug,
                nombre: nombre.trim(),
                descripcion: descripcion ? descripcion.trim() : "",
                duracion: parseInt(duracion),
                precio: Number(precio),
                capacidad: parseInt(capacidad) || 1,
                activo: true
            }])
            .select()
            .single();

        if (error) throw error;

        delete globalCache[cleanSlug];
        res.json({ success: true, servicio: data });
    } catch (e) {
        console.error("Error en POST /servicios/crear:", e.message);
        res.status(500).json({ error: e.message });
    }
});

// POST /servicios/editar — editar un servicio existente
app.post("/servicios/editar", async (req, res) => {
    try {
        const { id, slug, nombre, descripcion, duracion, precio, capacidad, activo } = req.body;
        const cleanSlug = getCleanSlug(slug);

        if (!id) {
            return res.status(400).json({ error: "Falta el id del servicio." });
        }

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
        console.error("Error en POST /servicios/editar:", e.message);
        res.status(500).json({ error: e.message });
    }
});

// POST /servicios/eliminar — eliminar un servicio
app.post("/servicios/eliminar", async (req, res) => {
    try {
        const { id, slug } = req.body;
        const cleanSlug = getCleanSlug(slug);

        if (!id) {
            return res.status(400).json({ error: "Falta el id del servicio." });
        }

        const { error } = await supabase
            .from("servicios")
            .delete()
            .eq("id", id)
            .eq("slug", cleanSlug);

        if (error) throw error;

        delete globalCache[cleanSlug];
        res.json({ success: true });
    } catch (e) {
        console.error("Error en POST /servicios/eliminar:", e.message);
        res.status(500).json({ error: e.message });
    }
});

// ==========================================================
// --- SLOTS DISPONIBLES CON CAPACIDAD ---
// ==========================================================

// GET /slots-disponibles/:slug — devuelve los slots con cuántos lugares quedan
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

        // Si viene un servicio_id usamos su duración y capacidad, si no usamos los globales
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

        // Verificar si la fecha es excepción
        if (user.excepciones && user.excepciones.includes(fecha)) {
            return res.json({ success: true, slots: [] });
        }

        // Obtener el día de la semana
        const diasSemana = ["domingo", "lunes", "martes", "miercoles", "jueves", "viernes", "sabado"];
        const fechaObj = new Date(fecha + "T12:00:00");
        const diaNombre = diasSemana[fechaObj.getDay()];
        const diaConfig = user.horarios?.[diaNombre];

        if (!diaConfig || !diaConfig.activo) {
            return res.json({ success: true, slots: [] });
        }

        // Generar todos los slots del día
        const [jornadaIni, jornadaFin] = diaConfig.jornada;
        const [descansoIni, descansoFin] = diaConfig.descanso || [null, null];

        const toMinutes = (timeStr) => {
            if (!timeStr) return null;
            const [h, m] = timeStr.split(":").map(Number);
            return h * 60 + m;
        };

        const fromMinutes = (mins) => {
            const h = Math.floor(mins / 60).toString().padStart(2, "0");
            const m = (mins % 60).toString().padStart(2, "0");
            return `${h}:${m}`;
        };

        const inicioJornada = toMinutes(jornadaIni);
        const finJornada = toMinutes(jornadaFin);
        const inicioDescanso = toMinutes(descansoIni);
        const finDescanso = toMinutes(descansoFin);

        const slotsGenerados = [];
        let cursor = inicioJornada;

        while (cursor + duracion <= finJornada) {
            const enDescanso = inicioDescanso && finDescanso && cursor >= inicioDescanso && cursor < finDescanso;
            if (!enDescanso) {
                slotsGenerados.push(fromMinutes(cursor));
            }
            cursor += duracion;
        }

        // Leer reservas existentes del sheet para esa fecha y slug
        const sheets = await getSheets();
        const sheetData = await sheets.spreadsheets.values.get({
            spreadsheetId: MASTER_SHEET_ID,
            range: "A:G"
        });

        const allRows = sheetData.data.values || [];
        const [anio, mes, dia] = fecha.split("-");
        const fechaFormateada = `${dia}/${mes}`;

        // Contar cuántas reservas hay por slot
        const reservasPorSlot = {};
        allRows.forEach((row, i) => {
            if (i === 0) return;
            const turnoFila = row[2]?.toString().trim();
            const slugFila = row[4]?.toString().toLowerCase().trim();
            if (slugFila !== slug || !turnoFila) return;
            const partes = turnoFila.split(" - ");
            if (partes.length < 2) return;
            const fechaFila = partes[0].trim();
            const horaFila = partes[1].trim();
            if (fechaFila === fechaFormateada) {
                reservasPorSlot[horaFila] = (reservasPorSlot[horaFila] || 0) + 1;
            }
        });

        // Armar respuesta con lugares disponibles por slot
        const slotsConDisponibilidad = slotsGenerados.map(slot => {
            const reservados = reservasPorSlot[slot] || 0;
            const disponibles = capacidad - reservados;
            return {
                hora: slot,
                disponibles: Math.max(0, disponibles),
                lleno: disponibles <= 0
            };
        });

        res.json({ success: true, slots: slotsConDisponibilidad });

    } catch (e) {
        console.error("Error en /slots-disponibles:", e.message);
        res.status(500).json({ error: e.message });
    }
});

// --- REGISTRO Y AUTH ---
app.post("/api/request-verification", async (req, res) => {
    try {
        // CORRECCIÓN: Extraemos 'business_name' que es lo que manda Framer
        const { 
            email, 
            business_name, 
            password, 
            plan, 
            precio, 
            duracion_turno, 
            tokens, 
            horarios 
        } = req.body;
        
        // Verificación de logs para debug en Render
        console.log("📩 Intento de registro para:", email, "Negocio:", business_name);

        // Validación estricta: usamos business_name
        if (!email || !business_name || !password) {
            return res.status(400).json({ 
                error: "Faltan datos obligatorios (email, negocio o pass)." 
            });
        }

        const googleRes = await fetch(APPS_SCRIPT_URL, {
            method: "POST",
            headers: { "Content-Type": "text/plain" },
            body: JSON.stringify({
                action: "sendCode",
                email: email.trim().toLowerCase(),
                usuario: business_name, // Enviamos el nombre correcto a Google
                password, 
                plan: plan || "gratis", 
                precio: precio || 0, 
                duracion_turno: duracion_turno || 30, 
                tokens: tokens || 0,
                horarios: typeof horarios === "string" ? horarios : JSON.stringify(horarios)
            })
        });

        const text = await googleRes.text();
        
        // Extracción segura del JSON de la respuesta de Google
        const start = text.indexOf('{');
        const end = text.lastIndexOf('}');
        
        if (start === -1 || end === -1) {
            console.error("Respuesta no válida de Google:", text);
            return res.status(500).json({ error: "Google Apps Script devolvió un formato inválido." });
        }

        const result = JSON.parse(text.substring(start, end + 1));
        
        if (result.status === "success") {
            console.log("✅ Código enviado con éxito a:", email);
            res.json({ success: true });
        } else {
            res.status(500).json({ error: result.message || "Error en Google Script" });
        }
    } catch (e) { 
        console.error("🔥 Error en request-verification:", e.message);
        res.status(500).json({ error: "Error de conexión con el servicio de correos." }); 
    }
});

app.post("/api/verify-and-register", async (req, res) => {
    try {
        const { 
            email, 
            code, 
            business_name, 
            nombre_persona, 
            precio, 
            duracion_turno, 
            plan, 
            horarios, 
            telefono 
        } = req.body;
        
        // 1. Validar el código de verificación con Google Apps Script
        const googleRes = await fetch(APPS_SCRIPT_URL, {
            method: "POST",
            headers: { "Content-Type": "text/plain" },
            body: JSON.stringify({ 
                action: "verifyCode", 
                email: email.trim().toLowerCase(), 
                code: code.toString().trim() 
            })
        });
        
        const result = await googleRes.json();

        if (result.status === "valid") {
            // 2. Generación de Slug
            const finalName = business_name || result.usuario || "Negocio";
            const cleanSlug = finalName
                .toLowerCase()
                .trim()
                .normalize("NFD")
                .replace(/[\u0300-\u036f]/g, "")
                .replace(/\s+/g, '-')
                .replace(/[^a-z0-9-]/g, '');

            // 3. Lógica de Plan y Vencimiento
            const isPremium = plan === 'premium';
            let fechaVencimientoInicial = null;
            
            if (isPremium) {
                const ahora = new Date();
                ahora.setMonth(ahora.getMonth() + 1); 
                fechaVencimientoInicial = ahora.toISOString();
            }

            const magicToken = crypto.randomBytes(16).toString('hex');

            // 4. Insertar en Supabase
            const { error } = await supabase.from('usuarios').insert([{
                slug: cleanSlug,
                email: email.trim().toLowerCase(),
                nombre_persona: nombre_persona ? nombre_persona.trim() : "Dueño",
                business_name: finalName.trim(),
                password: String(result.password),
                sheet_id: MASTER_SHEET_ID,
                precio: parseInt(precio) || 0,
                duracion_turno: parseInt(duracion_turno) || 30,
                horarios: horarios || {},
                plan: isPremium ? 'premium' : 'gratis',
                tokens: isPremium ? 100000 : 25,
                last_token_refresh: new Date().toISOString(),
                telefono: telefono || null,
                metodo_pago: isPremium ? 'manual' : 'none',
                subscription_expiry: fechaVencimientoInicial,
                excepciones: [],
                mp_access_token: null,
                access_token: magicToken
            }]);

            if (error) {
                if (error.code === '23505') {
                    return res.status(400).json({ 
                        error: "El nombre de este negocio ya está registrado. Intentá con uno distinto." 
                    });
                }
                throw error;
            }

            // --- 5. SEÑAL PARA MAIL DE BIENVENIDA (NUEVO) ---
            try {
                // No usamos await aquí si no queremos retrasar la respuesta al usuario, 
                // pero lo recomendable es usarlo para asegurar que la señal salga.
                await fetch(APPS_SCRIPT_URL, {
                    method: "POST",
                    headers: { "Content-Type": "text/plain" },
                    body: JSON.stringify({
                        action: "welcomeEmail",
                        email: email.trim().toLowerCase(),
                        usuario: finalName.trim()
                    })
                });
                console.log(`📧 Mail de bienvenida solicitado para: ${email}`);
            } catch (mailErr) {
                console.error("⚠️ Error al solicitar mail de bienvenida:", mailErr.message);
                // No cortamos el flujo, el usuario ya se registró correctamente.
            }

            // 6. Respuesta exitosa
            console.log(`✨ Nuevo usuario registrado exitosamente: ${cleanSlug}`);
            
            res.json({ 
                success: true, 
                slug: cleanSlug,
                at: magicToken,
                message: "¡Cuenta creada con éxito! Redirigiendo al panel..."
            });

        } else {
            res.status(400).json({ error: "El código de verificación es incorrecto." });
        }
    } catch (e) { 
        console.error("❌ Error crítico en registro:", e.message);
        res.status(500).json({ error: "No se pudo completar el registro." }); 
    }
});

app.post("/login", async (req, res) => {
    try {
        console.log("Login attempt:", req.body);
        const slug = getCleanSlug(req.body.slug);
        const { password } = req.body;

        const { data: user, error } = await supabase
            .from('usuarios')
            .select('*')
            .eq('slug', slug)
            .single();

        if (error || !user) {
            return res.status(401).json({ success: false, error: "Usuario no encontrado" });
        }

        if (String(user.password) === String(password)) {
            // --- NUEVO: Generamos un token también al loguearse manualmente ---
            const magicToken = crypto.randomBytes(16).toString('hex');
            
            await supabase
                .from('usuarios')
                .update({ access_token: magicToken })
                .eq('slug', slug);

            return res.json({ 
                success: true, 
                slug: user.slug,
                at: magicToken // <--- Se lo pasamos al front para que ProtectedRoute lo use
            });
        }

        res.status(401).json({ success: false, error: "Contraseña incorrecta" });
    } catch (e) { 
        console.error("Error en login:", e.message);
        res.status(500).json({ error: e.message }); 
    }
});

app.post("/api/request-password-reset", async (req, res) => {
    try {
        const { email, newPassword } = req.body;
        if (!email || !newPassword) return res.status(400).json({ error: "Faltan datos." });

        const { data: user, error } = await supabase
            .from('usuarios')
            .select('slug')
            .eq('email', email.trim().toLowerCase())
            .single();

        if (error || !user) return res.status(404).json({ error: "No existe una cuenta con ese correo." });

        const googleRes = await fetch(APPS_SCRIPT_URL, {
            method: "POST",
            headers: { "Content-Type": "text/plain" },
            body: JSON.stringify({
                action: "resetPassword",
                email: email.trim().toLowerCase(),
                newPassword: newPassword
            })
        });

        const text = await googleRes.text();
        const result = JSON.parse(text.substring(text.indexOf('{'), text.lastIndexOf('}') + 1));
        
        if (result.status === "success") res.json({ success: true });
        else res.status(500).json({ error: result.message });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post("/api/verify-and-reset-password", async (req, res) => {
    try {
        const { email, code } = req.body;
        const googleRes = await fetch(APPS_SCRIPT_URL, {
            method: "POST",
            headers: { "Content-Type": "text/plain" },
            body: JSON.stringify({ 
                action: "verifyCode", 
                email: email.trim().toLowerCase(), 
                code: code.toString().trim() 
            })
        });
        const result = await googleRes.json();
        if (result.status === "valid") {
            const { error } = await supabase
                .from('usuarios')
                .update({ password: String(result.password) })
                .eq('email', email.trim().toLowerCase());
            if (error) throw error;
            res.json({ success: true });
        } else {
            res.status(400).json({ error: "Código incorrecto o expirado." });
        }
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// --- ADMIN Y CONFIG ---
app.get("/admin-stats/:slug", async (req, res) => {
    const slug = getCleanSlug(req.params.slug);
    const now = Date.now();

    if (globalCache[slug] && (now - globalCache[slug].timestamp < CACHE_DURATION)) {
        return res.json(globalCache[slug].data);
    }

    try {
        try {
            await supabase.rpc("recargar_tokens_gratis");
        } catch (tokenError) {
            console.error("⚠️ Error al recargar tokens:", tokenError.message);
        }

        const { data: user, error: userError } = await supabase
            .from('usuarios')
            .select('*')
            .eq('slug', slug)
            .single();

        if (userError || !user) {
            return res.status(404).json({ error: "Usuario no encontrado" });
        }

        const ahoraArg = new Date(new Date().toLocaleString("en-US", { timeZone: "America/Argentina/Buenos_Aires" }));
        
        if (user.plan === 'premium') {
            const vencimiento = user.subscription_expiry ? new Date(user.subscription_expiry) : null;
            const hasActiveMagicToken = user.access_token !== null;

            if (!hasActiveMagicToken) {
                if (!vencimiento || ahoraArg > vencimiento) {
                    return res.status(402).json({ 
                        error: "Suscripción Premium vencida",
                        expired: true,
                        message: "Socio, tu suscripción Premium ha expirado. Por favor, renovala para seguir recibiendo turnos.",
                        slug: user.slug
                    });
                }
            }
        }

        const sheets = await getSheets();
        const response = await sheets.spreadsheets.values.get({ 
            spreadsheetId: MASTER_SHEET_ID, 
            range: "A:E" 
        });
        
        const allRows = response.data.values || [];
        const rows = allRows.filter((r, i) => i === 0 || (r[4] && getCleanSlug(r[4]) === slug));

        const mesActual = ahoraArg.getMonth() + 1;
        const diaHoyNum = ahoraArg.getDate();
        const anioActual = ahoraArg.getFullYear();
        
        let turnosHoy = 0;
        let turnosMesActual = 0;
        let turnosLista = [];
        let semanas = { "Sem 1": 0, "Sem 2": 0, "Sem 3": 0, "Sem 4": 0 };

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

                if (dia === diaHoyNum) {
                    turnosHoy++;
                }

                const etiquetaSemana = `Sem ${semanaIdx + 1}`;
                semanas[etiquetaSemana]++;
            }

            turnosLista.push({ 
                nombre: r[0], 
                telefono: r[1], 
                fecha: `${anioActual}-${String(mes).padStart(2, '0')}-${String(dia).padStart(2, '0')}`, 
                hora: partes[1], 
                semanaIdx: semanaIdx,
                duracion: user.duracion_turno || 60,
                rawTurno: r[2] 
            });
        });

        const finalData = {
            stats: {
                nombre_persona: user.nombre_persona,
                turnosHoy: turnosHoy,
                turnosMes: turnosMesActual,
                ingresosEstimados: turnosMesActual * (user.precio || 0),
                promedioDiario: diaHoyNum > 0 ? Math.round((turnosMesActual * (user.precio || 0)) / diaHoyNum) : 0,
                chartData: Object.keys(semanas).map(key => ({
                    label: key,
                    turnos: semanas[key]
                })),
                businessName: user.business_name,
                tokens: user.tokens,
                last_token_refresh: user.last_token_refresh || null,
                horarios: user.horarios,
                config: { 
                    duracion: user.duracion_turno, 
                    precio: user.precio, 
                    monto_sena: user.monto_sena || 0,
                    metodo_pago: user.metodo_pago || 'none',
                    mp_status: user.mp_access_token ? "Conectado" : "Desconectado", 
                    plan: user.plan,
                    vencimiento: user.subscription_expiry,
                    excepciones: user.excepciones || [] 
                },
                turnosLista: turnosLista.reverse()
            }
        };

        globalCache[slug] = {
            timestamp: now,
            data: finalData
        };

        res.json(finalData);

    } catch (e) { 
        console.error("❌ Error crítico en admin-stats:", e.message);
        res.status(500).json({ error: "Error al procesar las estadísticas del negeso." }); 
    }
});

app.post("/update-settings", async (req, res) => {
    try {
        const { slug, precio, horarios, duracion_turno, ocupados, monto_sena, cobrar_total_activado, metodo_pago } = req.body;
        const cleanSlug = getCleanSlug(slug);

        const numPrecio = parseInt(precio) || 0;
        const numSena = parseInt(monto_sena) || 0;

        let metodoPagoFinal = metodo_pago;
        if (!metodoPagoFinal) {
            if (numSena > 0) metodoPagoFinal = 'sena';
            else if (cobrar_total_activado) metodoPagoFinal = 'total';
            else metodoPagoFinal = 'none';
        }

        const updateData = { 
            precio: numPrecio,
            monto_sena: numSena,
            metodo_pago: metodoPagoFinal,
            duracion_turno: parseInt(duracion_turno) || 30
        };

        if (horarios) updateData.horarios = horarios;
        if (ocupados) updateData.excepciones = ocupados;

        const { error: updateError } = await supabase
            .from('usuarios')
            .update(updateData)
            .eq('slug', cleanSlug);

        if (updateError) throw updateError;
        delete globalCache[cleanSlug];
        res.json({ success: true });
    } catch (e) { 
        console.error("Error en update-settings:", e.message);
        res.status(500).json({ error: e.message }); 
    }
});

app.post("/cancel-appointment", async (req, res) => {
    try {
        const { slug, rawTurno } = req.body;
        const cleanSlug = getCleanSlug(slug);
        const sheets = await getSheets();
        const response = await sheets.spreadsheets.values.get({ spreadsheetId: MASTER_SHEET_ID, range: "A:E" });
        const rows = response.data.values || [];
        const rowIndex = rows.findIndex(r => r[2] === rawTurno && r[4] === cleanSlug);
        if (rowIndex === -1) return res.status(404).json({ error: "No encontrado" });
        
        const spreadsheet = await sheets.spreadsheets.get({ spreadsheetId: MASTER_SHEET_ID });
        const sheetIdReal = spreadsheet.data.sheets[0].properties.sheetId;
        await sheets.spreadsheets.batchUpdate({
            spreadsheetId: MASTER_SHEET_ID,
            requestBody: { requests: [{ deleteDimension: { range: { sheetId: sheetIdReal, dimension: "ROWS", startIndex: rowIndex, endIndex: rowIndex + 1 } } }] }
        });
        delete globalCache[cleanSlug];
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get("/verify-session", async (req, res) => {
    try {
        const rawU = req.query.u;
        const magicToken = req.query.at; 

        if (!rawU) {
            console.log("⚠️ Intento de verificación sin parámetro 'u' (slug)");
            return res.json({ active: false, reason: "no_slug" });
        }

        const slug = rawU.toLowerCase().trim().replace(/\s+/g, '-').replace(/[^a-z0-9-]/g, '');
        
        console.log(`🔍 Verificando sesión para el slug: [${slug}]`);

        const { data: user, error } = await supabase
            .from('usuarios')
            .select('slug, plan, subscription_expiry, access_token, tokens, business_name, email')
            .eq('slug', slug)
            .single();

        if (error || !user) {
            console.log(`❌ Usuario no encontrado en DB: ${slug}`);
            return res.json({ 
                active: false, 
                reason: "user_not_found",
                debug: error ? error.message : "Not found" 
            });
        }

        if (magicToken && user.access_token === magicToken) {
            console.log(`✨ Magic Login detectado para: ${slug}.`);
            
            await supabase
                .from('usuarios')
                .update({ access_token: null })
                .eq('slug', slug);
            
            const planFinal = user.plan === 'pendiente' ? 'premium' : user.plan;

            return res.json({ 
                active: true, 
                slug: user.slug, 
                plan: planFinal,
                business_name: user.business_name,
                email: user.email,
                magicLogin: true 
            });
        }

        if (user.plan === 'pendiente') {
            console.log(`⏳ El usuario ${slug} está en espera de confirmación de pago.`);
            return res.status(402).json({
                active: false,
                reason: "payment_pending",
                msg: "Tu suscripción se está procesando. Reintentá en 10 segundos."
            });
        }

        if (user.plan === 'premium') {
            if (user.subscription_expiry) {
                const ahora = new Date();
                const vencimiento = new Date(user.subscription_expiry);
                if (ahora > vencimiento) {
                    console.log(`🚫 Suscripción vencida para ${slug}. Redirigiendo a /renovar.`);
                    return res.status(402).json({ 
                        active: false, 
                        reason: "expired",
                        redirect: `/renovar?u=${slug}`,
                        expiry: user.subscription_expiry 
                    });
                }
            }
        }

        if (user.plan === 'gratis') {
            if (user.tokens === null || user.tokens <= 0) {
                console.log(`🚫 Sin tokens para: ${slug}. Redirigiendo a /freelimit.`);
                return res.status(402).json({
                    active: false,
                    reason: "no_tokens",
                    redirect: `/freelimit?u=${slug}`,
                    tokens: user.tokens
                });
            }
        }

        console.log(`✅ Sesión confirmada: ${slug} (Plan: ${user.plan})`);
        res.json({ 
            active: true, 
            slug: user.slug, 
            plan: user.plan,
            tokens: user.tokens,
            business_name: user.business_name,
            email: user.email
        });

    } catch (e) { 
        console.error("🔥 Error crítico en verify-session:", e.message);
        res.status(500).json({ 
            active: false, 
            error: "internal_server_error",
            msg: e.message 
        }); 
    }
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`🚀 Servidor NegoSocio en puerto ${PORT}`));
