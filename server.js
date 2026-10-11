"use strict";

const express = require("express");
const crypto = require("crypto");
const path = require("path");

const PORT = parseInt(process.env.PORT || "10000", 10);
const BASE_URL = (
  process.env.BASE_URL ||
  process.env.RENDER_EXTERNAL_URL ||
  `http://localhost:${PORT}`
).replace(/\/+$/, "");
const SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex");
const TITLE = process.env.APP_TITLE || "Lead Extractor";
const PRICE_CENTS = parseInt(process.env.PRICE_CENTS || "500", 10);
const CURRENCY = (process.env.CURRENCY || "usd").toLowerCase();
const FREE_LIMIT = parseInt(process.env.FREE_LIMIT || "10", 10);
const PASS_DAYS = parseInt(process.env.PASS_DAYS || "30", 10);

const stripe = process.env.STRIPE_SECRET_KEY
  ? require("stripe")(process.env.STRIPE_SECRET_KEY)
  : null;

// Checkout sessions that already issued a pass (in memory, resets on restart).
const usedSessions = new Set();

// ---------- access pass: "<expiry-ms>.<hmac>" stored in an httpOnly cookie ----------
function sign(value) {
  return crypto.createHmac("sha256", SECRET).update(value).digest("hex");
}

function makePass() {
  const exp = String(Date.now() + PASS_DAYS * 86400000);
  return `${exp}.${sign(exp)}`;
}

function validPass(token) {
  if (!token || typeof token !== "string") return false;
  const parts = token.split(".");
  if (parts.length !== 2) return false;
  const [exp, sig] = parts;
  const a = Buffer.from(sig);
  const b = Buffer.from(sign(exp));
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return false;
  return Number(exp) > Date.now();
}

function readCookie(req, name) {
  const header = req.headers.cookie || "";
  for (const part of header.split(";")) {
    const i = part.indexOf("=");
    if (i > -1 && part.slice(0, i).trim() === name) {
      return part.slice(i + 1).trim();
    }
  }
  return null;
}

// ---------- the actual tool: pull emails, phone numbers and links out of text ----------
const EMAIL_RE = /[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/gi;
const PHONE_RE = /(?:\+?1[\s.-]?)?(?:\(\d{3}\)|\d{3})[\s.-]?\d{3}[\s.-]?\d{4}\b/g;
const URL_RE = /\bhttps?:\/\/[^\s<>"')]+/gi;

function extract(text) {
  const seen = new Set();
  const items = [];
  const add = (type, value) => {
    const key = `${type}:${value}`;
    if (!seen.has(key)) {
      seen.add(key);
      items.push({ type, value });
    }
  };
  for (const m of text.match(EMAIL_RE) || []) add("email", m.toLowerCase());
  for (const m of text.match(PHONE_RE) || []) add("phone", m.trim());
  for (const m of text.match(URL_RE) || []) add("url", m.replace(/[.,;]+$/, ""));
  return items;
}

// ---------- server ----------
const app = express();
app.disable("x-powered-by");
app.use(express.json({ limit: "1mb" }));
app.use(express.static(path.join(__dirname, "public")));

app.get("/healthz", (_req, res) => res.json({ ok: true }));

app.get("/api/status", (req, res) => {
  res.json({
    title: TITLE,
    paid: validPass(readCookie(req, "pass")),
    freeLimit: FREE_LIMIT,
    priceCents: PRICE_CENTS,
    currency: CURRENCY,
    passDays: PASS_DAYS,
    paymentsConfigured: Boolean(stripe),
  });
});

app.post("/api/extract", (req, res) => {
  const text = req.body && typeof req.body.text === "string" ? req.body.text : "";
  if (!text.trim()) {
    return res.status(400).json({ error: "Paste some text first." });
  }
  const all = extract(text);
  const paid = validPass(readCookie(req, "pass"));
  const items = paid ? all : all.slice(0, FREE_LIMIT);
  res.json({ total: all.length, items, truncated: items.length < all.length, paid });
});

app.post("/api/checkout", async (_req, res) => {
  if (!stripe) {
    return res.status(503).json({ error: "Payments are not configured on this site yet." });
  }
  try {
    const session = await stripe.checkout.sessions.create({
      mode: "payment",
      line_items: [
        {
          price_data: {
            currency: CURRENCY,
            product_data: { name: `${TITLE} - ${PASS_DAYS}-day pass` },
            unit_amount: PRICE_CENTS,
          },
          quantity: 1,
        },
      ],
      success_url: `${BASE_URL}/success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${BASE_URL}/`,
      metadata: { app: TITLE },
    });
    res.json({ url: session.url });
  } catch (err) {
    console.error("checkout failed:", err.message);
    res.status(502).json({ error: "Could not start checkout. Please try again." });
  }
});

app.get("/success", async (req, res) => {
  const id = String(req.query.session_id || "");
  if (!stripe || !id) return res.redirect("/");
  try {
    const session = await stripe.checkout.sessions.retrieve(id);
    const ours = session.metadata && session.metadata.app === TITLE;
    if (session.payment_status === "paid" && ours && !usedSessions.has(id)) {
      usedSessions.add(id);
      const secure = BASE_URL.startsWith("https://") ? "; Secure" : "";
      res.setHeader(
        "Set-Cookie",
        `pass=${makePass()}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${PASS_DAYS * 86400}${secure}`
      );
      return res.redirect("/?paid=1");
    }
  } catch (err) {
    console.error("payment verification failed:", err.message);
  }
  res.redirect("/?paid=0");
});

module.exports = app;

if (require.main === module) {
  app.listen(PORT, "0.0.0.0", () => {
    console.log(`${TITLE} listening on ${PORT} (payments ${stripe ? "on" : "off"})`);
  });
}
