const express = require('express');
const cors = require('cors');
const Razorpay = require('razorpay');
const nodemailer = require('nodemailer');
const twilio = require('twilio');
const admin = require('firebase-admin');
const crypto = require('crypto');
require('dotenv').config();

const app = express();

// ─── CORS ─────────────────────────────────────────────────────────
// FIX: Lock to your actual frontend domain in production.
// During development you can add 'http://localhost:3000' etc.
const allowedOrigins = (process.env.ALLOWED_ORIGINS || '*').split(',').map(o => o.trim());
app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes('*') || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  }
}));
app.use(express.json());

// ─── FIREBASE INIT ───────────────────────────────────────────────
// FIX: FIREBASE_SERVICE_ACCOUNT must be valid JSON on ONE line in .env
let serviceAccount;
try {
  serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
} catch (e) {
  console.error('❌ FIREBASE_SERVICE_ACCOUNT is not valid JSON. Make sure it is on one line in your .env file.');
  process.exit(1);
}
admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
const db = admin.firestore();

// ─── RAZORPAY INIT ───────────────────────────────────────────────
const razorpay = new Razorpay({
  key_id:     process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET,
});

// ─── NODEMAILER INIT ─────────────────────────────────────────────
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.GMAIL_USER,     // e.g. yourname@gmail.com (no double @)
    pass: process.env.GMAIL_APP_PASS, // Gmail App Password
  },
});

// ─── TWILIO INIT ─────────────────────────────────────────────────
const twilioClient = twilio(
  process.env.TWILIO_ACCOUNT_SID,
  process.env.TWILIO_AUTH_TOKEN
);

// ─── SIMPLE RATE LIMITER (in-memory) ─────────────────────────────
// FIX: Prevent order-creation spam. Max 10 requests per IP per minute.
const rateLimitMap = new Map();
function rateLimit(req, res, next) {
  const ip = req.ip;
  const now = Date.now();
  const windowMs = 60 * 1000; // 1 minute
  const maxRequests = 10;

  if (!rateLimitMap.has(ip)) {
    rateLimitMap.set(ip, { count: 1, start: now });
    return next();
  }
  const entry = rateLimitMap.get(ip);
  if (now - entry.start > windowMs) {
    rateLimitMap.set(ip, { count: 1, start: now });
    return next();
  }
  if (entry.count >= maxRequests) {
    return res.status(429).json({ success: false, error: 'Too many requests. Please wait.' });
  }
  entry.count++;
  next();
}

// ─── ADMIN AUTH MIDDLEWARE ────────────────────────────────────────
// FIX: Centralise admin secret check
function adminAuth(req, res, next) {
  const secret = req.headers['x-admin-secret'];
  if (!secret || secret !== process.env.ADMIN_SECRET) {
    return res.status(401).json({ success: false, error: 'Unauthorized' });
  }
  next();
}

// ════════════════════════════════════════════════════════════════
//  ROUTE 1: Create Razorpay Order
// ════════════════════════════════════════════════════════════════
app.post('/api/create-order', rateLimit, async (req, res) => {
  try {
    const { amount, currency = 'INR', receipt } = req.body;

    if (!amount || typeof amount !== 'number' || amount <= 0) {
      return res.status(400).json({ success: false, error: 'Invalid amount.' });
    }

    const order = await razorpay.orders.create({
      amount: Math.round(amount * 100), // paise, ensure integer
      currency,
      receipt: receipt || `ff_${Date.now()}`,
    });

    res.json({ success: true, order });
  } catch (err) {
    console.error('Razorpay create-order error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ════════════════════════════════════════════════════════════════
//  ROUTE 2: Verify Payment + Save Order + Send Notifications
// ════════════════════════════════════════════════════════════════
app.post('/api/verify-payment', async (req, res) => {
  try {
    const {
      razorpay_order_id,
      razorpay_payment_id,
      razorpay_signature,
      orderData,
    } = req.body;

    // ── 1. Verify Razorpay signature ──────────────────────────────
    const expectedSig = crypto
      .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
      .update(`${razorpay_order_id}|${razorpay_payment_id}`)
      .digest('hex');

    if (expectedSig !== razorpay_signature) {
      return res.status(400).json({ success: false, error: 'Payment verification failed.' });
    }

    // ── 2. Validate required orderData fields ─────────────────────
    const required = ['name', 'email', 'phone', 'address', 'product', 'price'];
    for (const field of required) {
      if (!orderData?.[field]) {
        return res.status(400).json({ success: false, error: `Missing order field: ${field}` });
      }
    }

    // ── 3. Save order to Firebase ─────────────────────────────────
    const orderRef = await db.collection('orders').add({
      ...orderData,
      razorpay_order_id,
      razorpay_payment_id,
      status: 'confirmed',
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });
    const orderId = 'FF-' + orderRef.id.slice(-6).toUpperCase();
    await orderRef.update({ orderId });

    // ── 4. Send notifications (don't fail the response if they error) ─
    const notifyResults = await Promise.allSettled([
      sendEmail(orderData, orderId),
      sendWhatsApp(orderData, orderId),
    ]);

    notifyResults.forEach((r, i) => {
      if (r.status === 'rejected') {
        console.error(`Notification ${i === 0 ? 'email' : 'WhatsApp'} failed:`, r.reason?.message);
      }
    });

    res.json({ success: true, orderId });
  } catch (err) {
    console.error('Verify payment error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ════════════════════════════════════════════════════════════════
//  ROUTE 3: Get All Orders (Admin)
// ════════════════════════════════════════════════════════════════
app.get('/api/orders', adminAuth, async (req, res) => {
  try {
    const snapshot = await db.collection('orders')
      .orderBy('createdAt', 'desc')
      .limit(100)
      .get();

    const orders = [];
    snapshot.forEach(doc => orders.push({ id: doc.id, ...doc.data() }));
    res.json({ success: true, orders });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ════════════════════════════════════════════════════════════════
//  ROUTE 4: Admin Login (server-side auth)
//  FIX: Frontend should POST here instead of comparing passwords in JS
// ════════════════════════════════════════════════════════════════
app.post('/api/admin/login', async (req, res) => {
  const { username, password } = req.body;
  if (
    username === process.env.ADMIN_USER &&
    password === process.env.ADMIN_PASS
  ) {
    // Return the admin secret so frontend can use it for subsequent requests.
    // In production, use a signed JWT or httpOnly session cookie instead.
    res.json({ success: true, token: process.env.ADMIN_SECRET });
  } else {
    res.status(401).json({ success: false, error: 'Invalid credentials.' });
  }
});

// ════════════════════════════════════════════════════════════════
//  HELPER: Send Email
// ════════════════════════════════════════════════════════════════
async function sendEmail(order, orderId) {
  // Build items list (supports both multi-item cart and single item)
  const itemsHtml = Array.isArray(order.items)
    ? order.items.map(i =>
        `<tr>
          <td style="color:#555;padding:6px 0;font-size:0.75rem;">${i.name} (${i.size}) ×${i.qty}</td>
          <td style="color:#f0ede8;font-size:0.75rem;text-align:right;">₹${(i.price * i.qty).toLocaleString('en-IN')}</td>
        </tr>`
      ).join('')
    : `<tr>
        <td style="color:#555;padding:6px 0;font-size:0.75rem;">${order.product}</td>
        <td style="color:#f0ede8;font-size:0.75rem;text-align:right;">₹${Number(order.price).toLocaleString('en-IN')}</td>
      </tr>`;

  const html = `
  <div style="font-family:monospace;background:#0a0a0a;color:#f0ede8;padding:40px;max-width:560px;margin:0 auto;">
    <h1 style="font-size:2rem;margin-bottom:4px;">Freaky Frank</h1>
    <p style="color:#555;font-size:0.7rem;letter-spacing:3px;text-transform:uppercase;margin-bottom:32px;">Order Confirmation</p>
    <div style="border:1px solid #222;padding:24px;margin-bottom:24px;">
      <p style="color:#8b0000;font-size:0.6rem;letter-spacing:3px;text-transform:uppercase;margin-bottom:16px;">Order Details</p>
      <table style="width:100%;border-collapse:collapse;">
        ${itemsHtml}
        <tr style="border-top:1px solid #222;">
          <td style="color:#555;padding:10px 0 6px;font-size:0.75rem;">Total Paid</td>
          <td style="color:#f0ede8;font-size:0.9rem;text-align:right;font-style:italic;">₹${Number(order.price).toLocaleString('en-IN')}</td>
        </tr>
        <tr>
          <td style="color:#555;padding:6px 0;font-size:0.75rem;">Order ID</td>
          <td style="color:#8b0000;font-size:0.75rem;text-align:right;">${orderId}</td>
        </tr>
      </table>
    </div>
    <div style="border:1px solid #222;padding:24px;margin-bottom:24px;">
      <p style="color:#8b0000;font-size:0.6rem;letter-spacing:3px;text-transform:uppercase;margin-bottom:16px;">Shipping To</p>
      <p style="color:#f0ede8;font-size:0.75rem;margin:0">${order.name}</p>
      <p style="color:#888;font-size:0.75rem;margin:4px 0">${order.address}</p>
      <p style="color:#888;font-size:0.75rem;margin:0">${order.phone}</p>
    </div>
    <p style="color:#555;font-size:0.65rem;line-height:1.8;">Your order has been confirmed and will be dispatched within 2–3 business days. You will receive a shipping update once dispatched.</p>
    <p style="color:#333;font-size:0.6rem;margin-top:32px;">© 2026 Freaky Frank — Dark fashion for dark souls.</p>
  </div>`;

  // Confirmation to customer
  await transporter.sendMail({
    from: `"Freaky Frank" <${process.env.GMAIL_USER}>`,
    to: order.email,
    subject: `Order Confirmed — ${orderId} | Freaky Frank`,
    html,
  });

  // Notification to store owner
  await transporter.sendMail({
    from: `"Freaky Frank Orders" <${process.env.GMAIL_USER}>`,
    to: process.env.GMAIL_USER,
    subject: `🛒 New Order ${orderId} — ₹${Number(order.price).toLocaleString('en-IN')}`,
    html: `<pre style="font-family:monospace;background:#111;color:#f0ede8;padding:20px">${JSON.stringify({ orderId, ...order }, null, 2)}</pre>`,
  });
}

// ════════════════════════════════════════════════════════════════
//  HELPER: Send WhatsApp via Twilio
// ════════════════════════════════════════════════════════════════
async function sendWhatsApp(order, orderId) {
  // FIX: Clean phone number and ensure +91 prefix for Indian numbers
  const rawPhone = String(order.phone).replace(/[^0-9+]/g, '');
  const fullPhone = rawPhone.startsWith('+') ? rawPhone : '+91' + rawPhone;

  // Validate it looks like a real number
  if (fullPhone.replace(/[^0-9]/g, '').length < 10) {
    throw new Error(`Invalid phone number: ${order.phone}`);
  }

  // Build items list for the message
  const itemsList = Array.isArray(order.items)
    ? order.items.map(i => `• ${i.name} (${i.size}) ×${i.qty}`).join('\n')
    : `• ${order.product}`;

  const message =
    `✦ *Freaky Frank* — Order Confirmed!\n\n` +
    `*Order ID:* ${orderId}\n\n` +
    `*Items:*\n${itemsList}\n\n` +
    `*Total Paid:* ₹${Number(order.price).toLocaleString('en-IN')}\n\n` +
    `*Shipping to:*\n${order.name}\n${order.address}\n\n` +
    `Your order will be dispatched within 2–3 business days. 🖤\n` +
    `Thank you for shopping with us!`;

  await twilioClient.messages.create({
    from: `whatsapp:${process.env.TWILIO_WHATSAPP_FROM}`,
    to:   `whatsapp:${fullPhone}`,
    body: message,
  });
}

// ════════════════════════════════════════════════════════════════
//  HEALTH CHECK
// ════════════════════════════════════════════════════════════════
app.get('/', (req, res) => res.json({ status: 'Freaky Frank backend running ✦' }));

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`✦ Freaky Frank backend running on port ${PORT}`));
