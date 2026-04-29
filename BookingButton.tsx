import * as React from "react"
import { addPropertyControls, ControlType } from "framer"

// ─── BookingButton v4 ─────────────────────────────────────────────────────────
// Compatible con NegoSocio API v4 (slug-based, Supabase, service fee 2.5%)
// Flujo:
//   1. Lee datos del cliente desde localStorage (nombre, teléfono, fecha, hora, email)
//   2. Consulta /admin-stats/:slug?public=true para obtener config (SIN TOKEN)
//   3. Si requiere pago → llama a /api/create-preference → redirige a la pasarela
//   4. Si es gratis    → llama a /create-booking directamente
// ─────────────────────────────────────────────────────────────────────────────

export default function BookingButton(props) {
    const {
        baseUrl,
        buttonText,
        primaryColor,
        successUrl,
        errorUrl,
        alertUrl,
        manualSlug,
    } = props

    const [status, setStatus] = React.useState<"idle" | "loading">("idle")
    const [feeInfo, setFeeInfo] = React.useState<{
        fee: number
        total: number
    } | null>(null)

    // Resuelve el slug: ?u=fedeez en la URL tiene prioridad, luego manualSlug
    const getSlug = (): string => {
        if (typeof window === "undefined") return manualSlug || "default"
        const u = new URLSearchParams(window.location.search).get("u")
        if (u) return u.toLowerCase().trim()
        return (manualSlug || "default").trim()
    }

    // Al montar, previsualiza el service fee consultando la config del negocio
    React.useEffect(() => {
        const slug = getSlug()
        if (!slug || !baseUrl) return

        const cleanBase = baseUrl.replace(/\/$/, "")
        // ✅ USO: ?public=true, sin token
        fetch(`${cleanBase}/admin-stats/${slug}?public=true`)
            .then((r) => r.json())
            .then((data) => {
                const config = data?.stats?.config
                if (!config) return
                const precio = Number(config.precio || 0)
                const sena = Number(config.monto_sena || 0)
                const metodo = config.metodo_pago || "none"
                const montoBase = metodo === "sena" && sena > 0 ? sena : precio
                const fee = Math.round(precio * 0.025)
                setFeeInfo({ fee, total: montoBase + fee })
            })
            .catch((err) => {
                console.error("Error fetching config:", err)
            })
    }, [baseUrl, manualSlug])

    const handleBooking = async () => {
        const slug = getSlug()

        const name =
            localStorage.getItem("checkout_name") ||
            localStorage.getItem("name")
        const phone =
            localStorage.getItem("checkout_phone") ||
            localStorage.getItem("phone")
        const fecha = localStorage.getItem("checkout_fecha")
        const hora = localStorage.getItem("checkout_hora")
        const email = localStorage.getItem("checkout_email") || ""
        const servicioId =
            localStorage.getItem("checkout_servicio_id") || undefined

        if (!name || !phone || !fecha || !hora) {
            alert(
                "⚠️ Por favor, completá todos los datos y seleccioná un horario."
            )
            return
        }

        setStatus("loading")
        const cleanBase = baseUrl.replace(/\/$/, "")

        try {
            // 1. Obtener config del negocio (PÚBLICO, sin token)
            const statsRes = await fetch(
                `${cleanBase}/admin-stats/${slug}?public=true`
            )
            if (!statsRes.ok) throw new Error("Negocio no encontrado.")
            const statsData = await statsRes.json()
            const config = statsData?.stats?.config
            if (!config)
                throw new Error(
                    "No se pudo cargar la configuración del negocio."
                )

            const hasMP = config.mp_status === "Conectado"
            const hasMobbex = config.mobbex_status === "Conectado"
            const metodo = config.metodo_pago || "none"
            const debePagar =
                (hasMP || hasMobbex) &&
                (metodo === "sena" || metodo === "total")

            if (debePagar) {
                // 2a. Requiere pago → crear preferencia (MP o Mobbex según config del negocio)
                const prefRes = await fetch(
                    `${cleanBase}/api/create-preference`,
                    {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({
                            nombre: name,
                            telefono: phone,
                            email,
                            fecha,
                            hora,
                            slug,
                            servicio_id: servicioId,
                        }),
                    }
                )

                const prefData = await prefRes.json()

                if (!prefRes.ok)
                    throw new Error(
                        prefData.error || "Error al crear preferencia de pago."
                    )

                if (prefData.isFree) {
                    // Edge case: config cambió entre consultas, tratar como reserva libre
                    await hacerReservaDirecta(cleanBase, {
                        name,
                        phone,
                        email,
                        fecha,
                        hora,
                        slug,
                        servicioId,
                    })
                    return
                }

                if (prefData.payment_url) {
                    // Guardar el desglose en localStorage para mostrarlo en la página de pago si hace falta
                    localStorage.setItem(
                        "last_service_fee",
                        String(prefData.service_fee || 0)
                    )
                    localStorage.setItem(
                        "last_total_cobrado",
                        String(prefData.total_cobrado || 0)
                    )
                    localStorage.setItem(
                        "last_pasarela",
                        prefData.pasarela || ""
                    )
                    window.location.href = prefData.payment_url
                    return
                }

                throw new Error("No se generó el link de pago.")
            } else {
                // 2b. Gratis → reserva directa
                await hacerReservaDirecta(cleanBase, {
                    name,
                    phone,
                    email,
                    fecha,
                    hora,
                    slug,
                    servicioId,
                })
            }
        } catch (e: any) {
            console.error("BookingButton error:", e.message)
            if (errorUrl) {
                window.location.href = errorUrl
            } else {
                alert("❌ " + e.message)
                setStatus("idle")
            }
        }
    }

    const hacerReservaDirecta = async (
        cleanBase: string,
        { name, phone, email, fecha, hora, slug, servicioId }: any
    ) => {
        const res = await fetch(`${cleanBase}/create-booking`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                name,
                phone,
                email,
                fecha,
                hora,
                slug,
                servicio_id: servicioId,
            }),
        })
        const data = await res.json()

        if (res.ok && data.success) {
            window.location.href =
                successUrl || `https://${window.location.host}/success`
        } else if (res.status === 400 && alertUrl) {
            // 400 = turno duplicado
            window.location.href = alertUrl
        } else {
            throw new Error(data.error || "Error al crear la reserva.")
        }
    }

    const isLoading = status === "loading"

    return (
        <div
            style={{
                width: "100%",
                display: "flex",
                flexDirection: "column",
                gap: "8px",
            }}
        >
            {/* Preview del desglose de precios */}
            {feeInfo && feeInfo.fee > 0 && (
                <div style={feePreviewStyle}>
                    <span>Gasto de gestión</span>
                    <span style={{ color: "#666" }}>
                        +${feeInfo.fee.toLocaleString("es-AR")}
                    </span>
                </div>
            )}

            <button
                onClick={handleBooking}
                disabled={isLoading}
                style={{
                    width: "100%",
                    padding: "18px",
                    borderRadius: "14px",
                    backgroundColor: isLoading ? "#999" : primaryColor,
                    color: "#fff",
                    border: "none",
                    cursor: isLoading ? "not-allowed" : "pointer",
                    fontSize: "16px",
                    fontWeight: "600",
                    transition: "background-color 0.2s",
                }}
            >
                {isLoading
                    ? "Procesando..."
                    : feeInfo && feeInfo.fee > 0
                      ? `${buttonText} — $${feeInfo.total.toLocaleString("es-AR")}`
                      : buttonText}
            </button>
        </div>
    )
}

const feePreviewStyle: React.CSSProperties = {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    fontSize: "12px",
    color: "#999",
    padding: "4px 4px",
}

addPropertyControls(BookingButton, {
    baseUrl: {
        type: ControlType.String,
        title: "API URL",
        defaultValue: "https://negosocio.onrender.com",
    },
    manualSlug: {
        type: ControlType.String,
        title: "Slug Manual",
        placeholder: "fedeez",
        defaultValue: "",
    },
    buttonText: {
        type: ControlType.String,
        title: "Texto del Botón",
        defaultValue: "Confirmar Reserva",
    },
    primaryColor: {
        type: ControlType.Color,
        title: "Color",
        defaultValue: "#000000",
    },
    successUrl: {
        type: ControlType.String,
        title: "URL Éxito",
        defaultValue: "",
        placeholder: "https://tu-web.framer.website/success",
    },
    alertUrl: {
        type: ControlType.String,
        title: "URL Turno Duplicado",
        defaultValue: "",
        placeholder: "https://tu-web.framer.website/alert",
    },
    errorUrl: {
        type: ControlType.String,
        title: "URL Error",
        defaultValue: "",
        placeholder: "https://tu-web.framer.website/error",
    },
})
