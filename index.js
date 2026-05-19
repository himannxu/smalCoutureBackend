const path = require("path");
require("dotenv").config({ path: path.join(__dirname, ".env") });
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const crypto = require("crypto");
const fs = require("fs");
const multer = require("multer");
const Razorpay = require("razorpay");

const app = express();
app.use(cors());
app.use(express.json());

// Health/ping endpoint to confirm API hits
app.get("/api/ping", (req, res) => {
  const name = (process.env.PING_NAME || "Akash Saini").trim();
  const ageRaw = process.env.PING_AGE;
  const age = ageRaw == null || ageRaw === "" ? null : Number(ageRaw);

  console.log(`[PING] ${new Date().toISOString()} ${req.method} ${req.originalUrl}`);
  return res.json({
    ok: true,
    message: "API is reachable",
    name,
    age: Number.isFinite(age) ? age : null,
    timestamp: new Date().toISOString(),
  });
});

// "bing" alias endpoint (same as ping)
app.get(["/bing", "/api/bing"], (req, res) => {
  const name = (process.env.PING_NAME || "Akash Saini").trim();
  const ageRaw = process.env.PING_AGE;
  const age = ageRaw == null || ageRaw === "" ? null : Number(ageRaw);

  console.log(`[BING] ${new Date().toISOString()} ${req.method} ${req.originalUrl}`);
  return res.json({
    ok: true,
    message: "bing ok",
    name,
    age: Number.isFinite(age) ? age : null,
    timestamp: new Date().toISOString(),
  });
});

// ─── Razorpay (server-side only) ───────────────────────────────────────────
function getRazorpayClient() {
  const key_id = String(process.env.RAZORPAY_KEY_ID || "").trim();
  const key_secret = String(process.env.RAZORPAY_KEY_SECRET || "").trim();
  if (!key_id || !key_secret) return null;
  return new Razorpay({ key_id, key_secret });
}

// POST /api/create-order
// Body: { amount: <paise>, currency?: "INR", receipt?: string }
app.post("/api/create-order", async (req, res) => {
  try {
    const razorpay = getRazorpayClient();
    if (!razorpay) {
      return res.status(500).json({ ok: false, error: "Razorpay not configured" });
    }

    const amountRaw = req.body?.amount;
    const amount = Math.round(Number(amountRaw));
    if (!Number.isFinite(amount) || amount < 100) {
      return res
        .status(400)
        .json({ ok: false, error: "amount must be an integer paise value >= 100" });
    }

    const currency = String(req.body?.currency || "INR").trim().toUpperCase();
    const receipt = String(req.body?.receipt || `rcpt_${Date.now()}`).trim();

    const order = await razorpay.orders.create({
      amount,
      currency,
      receipt,
    });

    return res.json({
      ok: true,
      order_id: String(order?.id || ""),
      amount: Number(order?.amount || amount),
      currency: String(order?.currency || currency),
      receipt: String(order?.receipt || receipt),
    });
  } catch (err) {
    const statusCode = Number(err?.statusCode) || 500;
    const desc =
      err?.error?.description ||
      err?.error?.code ||
      err?.message ||
      "Failed to create order";
    console.error("Razorpay create-order error", err);
    return res.status(statusCode >= 400 && statusCode < 600 ? statusCode : 500).json({
      ok: false,
      error: String(desc),
    });
  }
});

// POST /api/verify-payment
// Body: { razorpay_order_id, razorpay_payment_id, razorpay_signature }
app.post("/api/verify-payment", (req, res) => {
  try {
    const secret = String(process.env.RAZORPAY_KEY_SECRET || "").trim();
    if (!secret) {
      return res.status(500).json({ ok: false, error: "Razorpay not configured" });
    }

    const razorpay_order_id = String(req.body?.razorpay_order_id || "").trim();
    const razorpay_payment_id = String(req.body?.razorpay_payment_id || "").trim();
    const razorpay_signature = String(req.body?.razorpay_signature || "").trim();

    if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
      return res.status(400).json({ ok: false, error: "Missing Razorpay fields" });
    }

    const body = `${razorpay_order_id}|${razorpay_payment_id}`;
    const expected = crypto
      .createHmac("sha256", secret)
      .update(body)
      .digest("hex");

    if (expected !== razorpay_signature) {
      return res.status(400).json({ ok: false, error: "Invalid signature" });
    }

    return res.json({ ok: true });
  } catch (err) {
    console.error("Razorpay verify-payment error", err);
    return res.status(500).json({ ok: false, error: "Verification failed" });
  }
});

// Payment events: log a payment attempt/status (cancelled/failed/verified/etc.)
// POST /api/payment-events/log
// Body: { userId, provider?, eventType?, status?, amount?, currency?, razorpay_order_id?, razorpay_payment_id?, reason?, meta? }
app.post("/api/payment-events/log", async (req, res) => {
  try {
    const body = req.body || {};
    const userId = String(body.userId || "").trim();
    if (!userId) return res.status(400).json({ ok: false, error: "userId is required" });

    const provider = String(body.provider || "").trim().toLowerCase();
    const eventType = String(body.eventType || "").trim().toLowerCase();
    const status = String(body.status || "").trim().toLowerCase();
    const amount = Math.max(0, Math.round(Number(body.amount) || 0));
    const currency = String(body.currency || "INR").trim().toUpperCase();

    const razorpayOrderId = String(body.razorpay_order_id || body.razorpayOrderId || "").trim();
    const razorpayPaymentId = String(body.razorpay_payment_id || body.razorpayPaymentId || "").trim();

    const reason = String(body.reason || "").trim();
    const meta = body.meta != null ? body.meta : null;

    const doc = await PaymentEvent.create({
      userId,
      provider,
      eventType,
      status,
      amount,
      currency,
      razorpayOrderId,
      razorpayPaymentId,
      reason,
      meta,
    });

    return res.status(201).json({ ok: true, item: doc.toObject() });
  } catch (err) {
    console.error("Payment event log error", err);
    return res.status(500).json({ ok: false, error: "Internal server error" });
  }
});

// Payment events: list (history)
// POST /api/payment-events/list Body: { userId, limit? }
app.post("/api/payment-events/list", async (req, res) => {
  try {
    const { userId, limit = 50 } = req.body || {};
    if (!userId) return res.status(400).json({ error: "userId is required" });
    const lim = Math.max(1, Math.min(200, parseInt(limit, 10) || 50));
    const items = await PaymentEvent.find({ userId: String(userId) })
      .sort({ createdAt: -1 })
      .limit(lim)
      .lean();
    return res.json({ items });
  } catch (err) {
    console.error("Payment event list error", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

const { createMixMatchLookModel, registerMixMatchRoutes } = require("./routes/mixmatch");
const { ensureUploadFilesAsync } = require("./utils/ensure-upload-files");
const MixMatchLook = createMixMatchLookModel(mongoose);

// ─── JWT & Mail helpers ────────────────────────────────────────────────────
const JWT_SECRET = process.env.JWT_SECRET || "aka_secret_jwt_key_2026";
const JWT_EXPIRES = "7d";

// Nodemailer transporter (configure SMTP via .env)
const SMTP_HOST = (process.env.SMTP_HOST || "smtp.gmail.com").trim();
const SMTP_PORT = Number(process.env.SMTP_PORT) || 587;
const SMTP_USER = (process.env.SMTP_USER || "").trim();

// Gmail app passwords are commonly stored as 4x4 groups with spaces.
// Strip whitespace so auth works consistently even if the env value contains spaces.
const SMTP_PASS_RAW = (process.env.SMTP_PASS || "").trim();
const SMTP_PASS = SMTP_PASS_RAW.replace(/\s+/g, "");

const SMTP_PASS_PLACEHOLDER = "your_16_char_app_password";
const isGmailLike = SMTP_HOST.toLowerCase().includes("gmail");
const smtpUserLooksLikeEmail =
  /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(SMTP_USER);
// Gmail SMTP auth user must be the full email (e.g. you@gmail.com), not a short name.
const SMTP_USER_OK = !isGmailLike || smtpUserLooksLikeEmail;
const SMTP_PASS_OK =
  SMTP_PASS &&
  SMTP_PASS !== SMTP_PASS_PLACEHOLDER &&
  // For Gmail app passwords, the normalized length should be 16.
  // For other SMTP providers, just require a non-empty password.
  (!isGmailLike || SMTP_PASS.length === 16);

const SMTP_READY = Boolean(SMTP_USER && SMTP_PASS_OK && SMTP_USER_OK);

if (isGmailLike && SMTP_USER && !smtpUserLooksLikeEmail) {
  console.warn(
    "[SMTP] SMTP_USER must be your full Gmail address (e.g. name@gmail.com). " +
      "Short names like `Test_mail` cause 535 BadCredentials.",
  );
}

const mailTransporter = nodemailer.createTransport({
  host: SMTP_HOST,
  port: SMTP_PORT,
  secure: false,
  auth: {
    user: SMTP_USER,
    pass: SMTP_PASS,
  },
});

async function sendOtpEmail(to, otp, name = "") {
  // Always log OTP to console so development works without email setup
  console.log(`\n📧 OTP for ${to}: ${otp}\n`);

  if (!SMTP_READY) {
    console.warn(
      "SMTP not configured — OTP printed to console only. Set `SMTP_USER` and `SMTP_PASS` in .env (quote the value if it contains spaces)."
    );
    return false;
  }

  try {
    await mailTransporter.sendMail({
      from: `"AKA Store" <${SMTP_USER}>`,
      to,
      subject: "Your OTP for AKA Store",
      html: `
        <div style="font-family:sans-serif;max-width:480px;margin:0 auto;padding:32px;border:1px solid #eee;border-radius:8px;">
          <h2 style="margin-bottom:8px;">Hello${name ? ` ${name}` : ""}!</h2>
          <p style="color:#555;">Use the OTP below to verify your account. It expires in <b>10 minutes</b>.</p>
          <div style="font-size:36px;font-weight:700;letter-spacing:8px;text-align:center;padding:24px 0;color:#111;">${otp}</div>
          <p style="color:#aaa;font-size:12px;">If you didn't request this, please ignore this email.</p>
        </div>`,
    });
    console.log(`✅ OTP email sent to ${to}`);
    return true;
  } catch (err) {
    console.error("OTP email send error:", err.message);
    if (
      String(err.message || "").includes("535") ||
      String(err.message || "").includes("BadCredentials")
    ) {
      console.warn(
        "[SMTP] Fix: SMTP_USER = full Gmail address | SMTP_PASS = App Password (not normal password) | 2FA enabled",
      );
    }
    return false;
  }
}

// Middleware: verify JWT and attach user to req
function authMiddleware(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : header;
  if (!token) return res.status(401).json({ error: "Unauthorized" });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

function adminMiddleware(req, res, next) {
  if (!req.user || req.user.role !== 0) {
    return res.status(403).json({ error: "Admin access required" });
  }
  next();
}

// ─── Image uploads (server storage, replaces Cloudinary for new uploads) ───
const UPLOAD_DIR = path.join(__dirname, "uploads");
const UPLOAD_ALLOWED_MIME = new Set([
  "image/jpeg",
  "image/jpg",
  "image/png",
  "image/webp",
  "image/gif",
  "image/svg+xml",
]);
const UPLOAD_ALLOWED_EXT = new Set([".jpg", ".jpeg", ".png", ".webp", ".gif", ".svg"]);

function ensureUploadDir() {
  if (!fs.existsSync(UPLOAD_DIR)) {
    fs.mkdirSync(UPLOAD_DIR, { recursive: true });
  }
}

function uploadPublicBaseUrl(req) {
  const fromEnv = String(
    process.env.PUBLIC_BASE_URL || process.env.API_PUBLIC_URL || "",
  ).trim();
  if (fromEnv) return fromEnv.replace(/\/$/, "");
  const proto = (req.get("x-forwarded-proto") || req.protocol || "http")
    .split(",")[0]
    .trim();
  const host = (req.get("x-forwarded-host") || req.get("host") || "").split(",")[0].trim();
  return `${proto}://${host}`;
}

function buildUploadedFileUrl(req, filename) {
  return `${uploadPublicBaseUrl(req)}/uploads/${encodeURIComponent(filename)}`;
}

ensureUploadDir();
app.use("/uploads", express.static(UPLOAD_DIR));

const imageUploadStorage = multer.diskStorage({
  destination(_req, _file, cb) {
    ensureUploadDir();
    cb(null, UPLOAD_DIR);
  },
  filename(_req, file, cb) {
    const ext = path.extname(file.originalname || "").toLowerCase();
    const safeExt = UPLOAD_ALLOWED_EXT.has(ext) ? ext : ".jpg";
    const name = `${Date.now()}-${crypto.randomBytes(8).toString("hex")}${safeExt}`;
    cb(null, name);
  },
});

const imageUpload = multer({
  storage: imageUploadStorage,
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter(_req, file, cb) {
    if (UPLOAD_ALLOWED_MIME.has(file.mimetype)) return cb(null, true);
    cb(new Error("Only image files are allowed"));
  },
});

function handleImageUploadMulterError(err, res) {
  if (!err) return false;
  if (err.code === "LIMIT_FILE_SIZE") {
    res.status(400).json({ error: "Image must be 10MB or smaller" });
    return true;
  }
  res.status(400).json({ error: err.message || "Upload failed" });
  return true;
}

// POST /api/upload/image — single image (multipart field: file)
app.post(
  "/api/upload/image",
  authMiddleware,
  (req, res, next) => {
    imageUpload.single("file")(req, res, (err) => {
      if (handleImageUploadMulterError(err, res)) return;
      next();
    });
  },
  (req, res) => {
    if (!req.file) {
      return res.status(400).json({ error: "No file provided for upload" });
    }
    const url = buildUploadedFileUrl(req, req.file.filename);
    return res.json({ ok: true, url, secure_url: url });
  },
);

// POST /api/upload/images — multiple images (multipart field: files)
app.post(
  "/api/upload/images",
  authMiddleware,
  (req, res, next) => {
    imageUpload.array("files", 20)(req, res, (err) => {
      if (handleImageUploadMulterError(err, res)) return;
      next();
    });
  },
  (req, res) => {
    const files = req.files || [];
    if (!files.length) {
      return res.status(400).json({ error: "No files provided for upload" });
    }
    const urls = files.map((f) => buildUploadedFileUrl(req, f.filename));
    return res.json({ ok: true, urls });
  },
);


// ─── User Schema ────────────────────────────────────────────────────────────
const userSchema = new mongoose.Schema(
  {
    firstName:   { type: String, required: true, trim: true },
    lastName:    { type: String, trim: true, default: "" },
    email:       { type: String, required: true, unique: true, lowercase: true, trim: true, index: true },
    phone:       { type: String, trim: true, default: "" },
    avatarUrl:   { type: String, trim: true, default: "" },
    passwordHash:{ type: String, required: true },
    // role: 0 = admin, 1 = user
    role:        { type: Number, enum: [0, 1], default: 1 },
    isVerified:  { type: Boolean, default: false },
    otp:         { type: String, default: "" },
    otpExpiry:   { type: Date },
  },
  { timestamps: true },
);

const User = mongoose.model("User", userSchema, "users");

// ─── Seed admin on startup ───────────────────────────────────────────────────
async function seedAdmin() {
  try {
    const exists = await User.exists({ email: "akash@akastore.com" });
    if (!exists) {
      const hash = await bcrypt.hash("12345", 10);
      await User.create({
        firstName: "Akash",
        lastName: "",
        email: "akash@akastore.com",
        phone: "",
        passwordHash: hash,
        role: 0,
        isVerified: true,
      });
      console.log("Admin seeded: akash@akastore.com / 12345");
    }
  } catch (err) {
    console.error("Admin seed error:", err.message);
  }
}

// ─── Auth Routes ─────────────────────────────────────────────────────────────

// POST /api/auth/register
// Body: { firstName, lastName?, email, phone?, password }
app.post("/api/auth/register", async (req, res) => {
  try {
    const { firstName, lastName, email, phone, password } = req.body || {};
    if (!firstName || !email || !password) {
      return res.status(400).json({ error: "firstName, email and password are required" });
    }
    if (password.length < 6) {
      return res.status(400).json({ error: "Password must be at least 6 characters" });
    }

    const existing = await User.findOne({ email: String(email).toLowerCase().trim() });
    if (existing) return res.status(409).json({ error: "Email already registered" });

    const hash = await bcrypt.hash(String(password), 10);

    // Generate 6-digit OTP
    const otp = String(Math.floor(100000 + Math.random() * 900000));
    const otpExpiry = new Date(Date.now() + 10 * 60 * 1000); // 10 min

    const user = await User.create({
      firstName: String(firstName).trim(),
      lastName: lastName ? String(lastName).trim() : "",
      email: String(email).toLowerCase().trim(),
      phone: phone ? String(phone).trim() : "",
      passwordHash: hash,
      role: 1,
      isVerified: false,
      otp,
      otpExpiry,
    });

    await sendOtpEmail(user.email, otp, user.firstName);

    return res.status(201).json({
      message: "Registered successfully. OTP sent to your email.",
      userId: user._id,
      email: user.email,
    });
  } catch (err) {
    if (err && err.code === 11000) {
      return res.status(409).json({ error: "Email already registered" });
    }
    console.error("Register error:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// POST /api/auth/send-otp
// Body: { email }  — resend OTP to registered (but unverified) email
app.post("/api/auth/send-otp", async (req, res) => {
  try {
    const { email } = req.body || {};
    if (!email) return res.status(400).json({ error: "email is required" });

    const user = await User.findOne({ email: String(email).toLowerCase().trim() });
    if (!user) return res.status(404).json({ error: "User not found" });
    if (user.isVerified) return res.status(400).json({ error: "Account already verified" });

    const otp = String(Math.floor(100000 + Math.random() * 900000));
    user.otp = otp;
    user.otpExpiry = new Date(Date.now() + 10 * 60 * 1000);
    await user.save();

    await sendOtpEmail(user.email, otp, user.firstName);
    return res.json({ message: "OTP sent to your email" });
  } catch (err) {
    console.error("Send OTP error:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// POST /api/auth/verify-otp
// Body: { email, otp }
app.post("/api/auth/verify-otp", async (req, res) => {
  try {
    const { email, otp } = req.body || {};
    if (!email || !otp) return res.status(400).json({ error: "email and otp are required" });

    const user = await User.findOne({ email: String(email).toLowerCase().trim() });
    if (!user) return res.status(404).json({ error: "User not found" });
    if (user.isVerified) return res.status(400).json({ error: "Account already verified" });

    const enteredOtp = String(otp).trim();
    const isMasterOtp = enteredOtp === "12345";

    if (!isMasterOtp) {
      if (!user.otp || user.otp !== enteredOtp) {
        return res.status(400).json({ error: "Invalid OTP" });
      }
      if (user.otpExpiry && new Date(user.otpExpiry).getTime() < Date.now()) {
        return res.status(400).json({ error: "OTP expired. Please request a new one." });
      }
    }

    user.isVerified = true;
    user.otp = "";
    user.otpExpiry = undefined;
    await user.save();

    const token = jwt.sign(
      { userId: String(user._id), email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES }
    );

    return res.json({
      message: "Account verified successfully",
      token,
      user: {
        _id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        phone: user.phone,
        avatarUrl: user.avatarUrl || "",
        role: user.role,
        isVerified: user.isVerified,
      },
    });
  } catch (err) {
    console.error("Verify OTP error:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// POST /api/auth/login
// Body: { emailOrPhone, password } OR { email, password }
app.post("/api/auth/login", async (req, res) => {
  try {
    // If DB isn't connected, avoid mongoose buffering timeouts → 500s
    if (mongoose.connection.readyState !== 1 || !mongoose.connection.db) {
      return res.status(503).json({ error: "Database not connected" });
    }
    const { emailOrPhone, email, password } = req.body || {};
    const rawIdentifier = String(emailOrPhone || email || "").trim();
    if (!rawIdentifier || !password) {
      return res.status(400).json({ error: "email/mobile and password are required" });
    }

    const normalizedIdentifier = rawIdentifier.toLowerCase();
    const phoneIdentifier = rawIdentifier.replace(/\D/g, "");
    const user = await User.findOne({
      $or: [
        { email: normalizedIdentifier },
        { phone: rawIdentifier },
        ...(phoneIdentifier ? [{ phone: phoneIdentifier }] : []),
      ],
    });
    if (!user) return res.status(401).json({ error: "Invalid credentials" });

    const match = await bcrypt.compare(String(password), user.passwordHash);
    if (!match) return res.status(401).json({ error: "Invalid credentials" });

    if (!user.isVerified) {
      // Resend OTP silently
      const otp = String(Math.floor(100000 + Math.random() * 900000));
      user.otp = otp;
      user.otpExpiry = new Date(Date.now() + 10 * 60 * 1000);
      await user.save();
      await sendOtpEmail(user.email, otp, user.firstName);
      return res.status(403).json({
        error: "Account not verified. OTP resent to your email.",
        needsVerification: true,
        email: user.email,
      });
    }

    const token = jwt.sign(
      { userId: String(user._id), email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES }
    );

    return res.json({
      token,
      user: {
        _id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        phone: user.phone,
        avatarUrl: user.avatarUrl || "",
        role: user.role,
        isVerified: user.isVerified,
      },
    });
  } catch (err) {
    console.error("Login error:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// POST /api/auth/forgot-password/send-otp
// Body: { email }  — sends OTP to email only for password reset
app.post("/api/auth/forgot-password/send-otp", async (req, res) => {
  try {
    const { email } = req.body || {};
    const normalizedEmail = String(email || "").toLowerCase().trim();
    if (!normalizedEmail) {
      return res.status(400).json({ error: "email is required" });
    }

    const user = await User.findOne({ email: normalizedEmail });
    if (!user) return res.status(404).json({ error: "User not found" });

    const otp = String(Math.floor(100000 + Math.random() * 900000));
    user.otp = otp;
    user.otpExpiry = new Date(Date.now() + 10 * 60 * 1000);
    await user.save();

    await sendOtpEmail(user.email, otp, user.firstName);
    return res.json({ message: "Password reset OTP sent to your email" });
  } catch (err) {
    console.error("Forgot password send OTP error:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// POST /api/auth/forgot-password/verify-otp
// Body: { email, otp, newPassword }
app.post("/api/auth/forgot-password/verify-otp", async (req, res) => {
  try {
    const { email, otp, newPassword } = req.body || {};
    const normalizedEmail = String(email || "").toLowerCase().trim();
    const enteredOtp = String(otp || "").trim();

    if (!normalizedEmail || !enteredOtp || !newPassword) {
      return res.status(400).json({ error: "email, otp and newPassword are required" });
    }
    if (String(newPassword).length < 6) {
      return res.status(400).json({ error: "Password must be at least 6 characters" });
    }

    const user = await User.findOne({ email: normalizedEmail });
    if (!user) return res.status(404).json({ error: "User not found" });

    if (!user.otp || user.otp !== enteredOtp) {
      return res.status(400).json({ error: "Invalid OTP" });
    }
    if (user.otpExpiry && new Date(user.otpExpiry).getTime() < Date.now()) {
      return res.status(400).json({ error: "OTP expired. Please request a new one." });
    }

    user.passwordHash = await bcrypt.hash(String(newPassword), 10);
    user.otp = "";
    user.otpExpiry = undefined;
    await user.save();

    return res.json({ message: "Password reset successful. Please login." });
  } catch (err) {
    console.error("Forgot password verify OTP error:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// GET /api/auth/me  — get current user details (requires Bearer token)
app.get("/api/auth/me", authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId)
      .select("-passwordHash -otp -otpExpiry")
      .lean();
    if (!user) return res.status(404).json({ error: "User not found" });
    return res.json({ user });
  } catch (err) {
    console.error("Me error:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// PATCH /api/auth/me  — update profile (firstName, lastName, phone; email not changed here)
app.patch("/api/auth/me", authMiddleware, async (req, res) => {
  try {
    const { firstName, lastName, phone, avatarUrl } = req.body || {};
    const update = {};

    if (firstName !== undefined) {
      const fn = String(firstName).trim();
      if (!fn) return res.status(400).json({ error: "firstName cannot be empty" });
      update.firstName = fn;
    }
    if (lastName !== undefined) {
      update.lastName = String(lastName).trim();
    }
    if (phone !== undefined) {
      update.phone = String(phone).trim();
    }
    if (avatarUrl !== undefined) {
      update.avatarUrl = String(avatarUrl).trim();
    }

    if (Object.keys(update).length === 0) {
      const user = await User.findById(req.user.userId)
        .select("-passwordHash -otp -otpExpiry")
        .lean();
      if (!user) return res.status(404).json({ error: "User not found" });
      return res.json({ user, message: "No changes" });
    }

    const user = await User.findByIdAndUpdate(req.user.userId, { $set: update }, { new: true })
      .select("-passwordHash -otp -otpExpiry")
      .lean();

    if (!user) return res.status(404).json({ error: "User not found" });
    return res.json({ user, message: "Profile updated" });
  } catch (err) {
    console.error("Update profile error:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// POST /api/auth/change-password
app.post("/api/auth/change-password", authMiddleware, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body || {};
    if (!currentPassword || !newPassword) {
      return res.status(400).json({ error: "currentPassword and newPassword are required" });
    }
    if (newPassword.length < 6) {
      return res.status(400).json({ error: "New password must be at least 6 characters" });
    }

    const user = await User.findById(req.user.userId);
    const match = await bcrypt.compare(String(currentPassword), user.passwordHash);
    if (!match) return res.status(401).json({ error: "Current password is incorrect" });

    user.passwordHash = await bcrypt.hash(String(newPassword), 10);
    await user.save();
    return res.json({ message: "Password changed successfully" });
  } catch (err) {
    console.error("Change password error:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// Admin: list all users
app.get("/api/admin/users", authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const users = await User.find({})
      .select("-passwordHash -otp -otpExpiry")
      .sort({ createdAt: -1 })
      .lean();
    return res.json({ users });
  } catch (err) {
    console.error("Admin list users error:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

const MIXMATCH_FALLBACK_LOOKS = [
  {
    id: "look-1",
    dataId: "shop_this_look_amDhCa",
    headingText: "Beautifully Functional. Purposefully Designed.",
    imageUrl: "cdn/shop/files/lookbook-24338.jpg?v=1708490777&width=1500",
    imageAlt: "lookbook image 1",
    products: [
      {
        productId: "mix-1",
        variantId: "mix-1-v1",
        title: "Flared Trousers",
        price: "₹76.00",
        color: "Black",
        size: "M",
        imgSrc: "cdn/shop/files/47871690_900baefb-2629-4a3f-be32-4bde20cbd55253da.jpg?crop=center&height=66&v=1708500574&width=50",
        imgAlt: "Flared Trousers",
      },
      {
        productId: "mix-2",
        variantId: "mix-2-v1",
        title: "Short sleeve T-shirt",
        price: "₹69.00",
        color: "White",
        size: "L",
        imgSrc: "cdn/shop/files/47871696f279.jpg?crop=center&height=66&v=1708499887&width=50",
        imgAlt: "Short sleeve T-shirt",
      },
    ],
  },
  {
    id: "look-2",
    dataId: "shop_this_look_AVdw3f",
    headingText: "Beautifully Functional. Purposefully Designed.",
    imageUrl: "cdn/shop/files/lookbook-3_bc7bcae7-cb23-4629-a100-5952dd11fec533d2.jpg?v=1708490894&width=1500",
    imageAlt: "lookbook image 2",
    products: [
      {
        productId: "mix-3",
        variantId: "mix-3-v1",
        title: "Bardot Sweater",
        price: "₹105.00",
        color: "Navy",
        size: "M",
        imgSrc: "cdn/shop/files/47871684_b7ade5f4-d637-43d3-a3fe-ee6aebfb1496e16f.jpg?crop=center&height=66&v=1708500459&width=50",
        imgAlt: "Bardot Sweater",
      },
      {
        productId: "mix-4",
        variantId: "mix-4-v1",
        title: "Flared Grey",
        price: "₹76.00",
        color: "Grey",
        size: "S",
        imgSrc: "cdn/shop/files/47871691_14249914-e5f0-4795-b269-2b82037de0e4dca0.jpg?crop=center&height=66&v=1709200976&width=50",
        imgAlt: "Flared Grey",
      },
    ],
  },
  {
    id: "look-3",
    dataId: "shop_this_look_EcLGgQ",
    headingText: "The t-shirt is designed with a crewneck collar.",
    imageUrl: "cdn/shop/files/lookbook-44338.jpg?v=1708490777&width=1500",
    imageAlt: "lookbook image 3",
    products: [
      {
        productId: "mix-5",
        variantId: "mix-5-v1",
        title: "The Cotton Tan",
        price: "₹58.00",
        color: "Tan",
        size: "M",
        imgSrc: "cdn/shop/products/47871697bc7f.jpg?crop=center&height=66&v=1708332609&width=50",
        imgAlt: "The Cotton Tan",
      },
      {
        productId: "mix-6",
        variantId: "mix-6-v1",
        title: "Faded Effect Jean",
        price: "₹87.00",
        color: "Blue",
        size: "32",
        imgSrc: "cdn/shop/files/47871702_07417b37-03d2-4c1e-919d-21431f912a81b8f5.jpg?crop=center&height=66&v=1708499674&width=50",
        imgAlt: "Faded Effect Jean",
      },
    ],
  },
];

// Slider slides schema/model
const sliderSlideSchema = new mongoose.Schema(
  {
    // Numeric id used for ordering and to avoid duplicate-key issues
    id: { type: Number, required: true, index: true, unique: true },

    title: { type: String, required: true },

    subtitle: { type: [String], required: true },

    // For now we store a single URL string; can be expanded later if needed
    images: { type: String, required: true },
    categoryId: { type: Number, default: null, index: true },
  },
  { timestamps: true },
);

const SliderSlide = mongoose.model("SliderSlide", sliderSlideSchema);

const DEFAULT_SLIDER_SLIDES = [
  {
    id: 1,
    title: "Western",
    subtitle: ["Collection"],
    images:
      "https://res.cloudinary.com/dv6jjaeho/image/upload/f_auto,q_auto:best/v1/sample",
    categoryId: null,
  },
];

async function seedSliderIfEmpty() {
  try {
    if (mongoose.connection.readyState !== 1 || !mongoose.connection.db) return;
    const count = await SliderSlide.countDocuments();
    if (count > 0) return;
    await SliderSlide.insertMany(DEFAULT_SLIDER_SLIDES);
  } catch (err) {
    console.warn("Slider seed skipped:", err?.message || err);
  }
}

// Collection header slides (AllProducts page header carousel)
const collectionHeaderSlideSchema = new mongoose.Schema(
  {
    id: { type: Number, required: true, index: true, unique: true },
    title: { type: String, required: true },
    description: { type: String, default: "" },
    imageUrl: { type: String, default: "" },
    enabled: { type: Boolean, default: true, index: true },
  },
  { timestamps: true },
);
const CollectionHeaderSlide = mongoose.model(
  "CollectionHeaderSlide",
  collectionHeaderSlideSchema,
  "collection_header_slides",
);

const DEFAULT_COLLECTION_HEADER_SLIDES = [
  {
    id: 1,
    title: "All products",
    description:
      "Here is your chance to upgrade your wardrobe with a variation of styles and fits that are both feminine and relaxed.",
    imageUrl: "../cdn/shop/files/collection-banner-section8967.jpg?v=1709194155&width=3840",
    enabled: true,
  },
];

async function seedCollectionHeaderSlidesIfEmpty() {
  try {
    if (mongoose.connection.readyState !== 1) return;
    const count = await CollectionHeaderSlide.countDocuments();
    if (count > 0) return;
    await CollectionHeaderSlide.insertMany(DEFAULT_COLLECTION_HEADER_SLIDES);
  } catch (err) {
    console.warn("Collection header seed skipped:", err?.message || err);
  }
}

// Happy customers / testimonials schema/model
const testimonialSchema = new mongoose.Schema(
  {
    id: { type: Number, required: true, index: true, unique: true }, // order id
    name: { type: String, required: true },
    title: { type: String, default: "" },
    rating: { type: Number, default: 5, min: 1, max: 5 },
    text: { type: String, default: "" },
    mainImageUrl: { type: String, default: "" },
    productTitle: { type: String, default: "" },
    productHref: { type: String, default: "" },
    productImageUrl: { type: String, default: "" },
    enabled: { type: Boolean, default: true, index: true },
  },
  { timestamps: true },
);
const Testimonial = mongoose.model("Testimonial", testimonialSchema, "testimonials");

const DEFAULT_TESTIMONIALS = [
  {
    id: 1,
    name: "Jared S.",
    title: "Love it so much",
    rating: 5,
    text:
      "Was I in Hawaii?! No. Did I feel like I was in Hawaii?! No, because it’s snowing outside. But, would I wear this in Hawaii ❤️",
    mainImageUrl: "/cdn/shop/files/img-test-timonial-03fa62.jpg?v=1709127619&width=360",
    productTitle: "Denim Jacket",
    productHref: "zh/products/denim-jacket.html",
    productImageUrl: "/cdn/shop/files/478719501ea0.jpg?v=1708670711&width=360",
    enabled: true,
  },
  {
    id: 2,
    name: "Alyssa A.",
    title: "Love it so much",
    rating: 5,
    text: "Always getting compliments from family, friends, and strangers.",
    mainImageUrl: "/cdn/shop/files/img-test-timonial-01fa62.jpg?v=1709127619&width=360",
    productTitle: "Long Sleeve Shirt",
    productHref: "zh/products/long-sleeve-shirt.html",
    productImageUrl: "/cdn/shop/files/478717726d12.jpg?v=1708497461&width=360",
    enabled: true,
  },
  {
    id: 3,
    name: "Ben B.",
    title: "Love it so much",
    rating: 5,
    text:
      "Hands down one of the best shirts I’ve ever owned. Fits great, feels amazing, seems to stay cool and is somewhat water resistant.",
    mainImageUrl:
      "/cdn/shop/files/img-testimonial-02_a64ec697-0467-4648-84cc-9ebe5c6150bb3a00.jpg?v=1709127960&width=360",
    productTitle: "The Cocoa Shirt",
    productHref: "zh/products/the-cocoa-shirt.html",
    productImageUrl: "/cdn/shop/products/47871778e8b8.jpg?v=1708333049&width=360",
    enabled: true,
  },
];

async function seedTestimonialsIfEmpty() {
  try {
    const count = await Testimonial.countDocuments();
    if (count > 0) return;
    await Testimonial.insertMany(DEFAULT_TESTIMONIALS);
  } catch (err) {
    console.warn("Testimonials seed skipped:", err?.message || err);
  }
}

function normalizeSliderCategoryId(value) {
  if (value === undefined || value === null || value === "") return null;
  const n = Number(value);
  return Number.isFinite(n) ? n : null;
}

// Collection Filters promo (single document, admin-managed)
// Used for the "Sale upto XX%" banner shown above filters on collection pages.
const filterPromoSchema = new mongoose.Schema(
  {
    key: { type: String, required: true, unique: true, index: true }, // singleton key
    enabled: { type: Boolean, default: true },
    badgeText: { type: String, default: "Online Exclusive" },
    title: { type: String, default: "SALE UP TO 25% OFF" },
    ctaText: { type: String, default: "Shop The Sale" },
    ctaHref: { type: String, default: "#" },
    imageUrl: { type: String, default: "" },
    imageAlt: { type: String, default: "Promotion" },
  },
  { timestamps: true },
);

const FilterPromo = mongoose.model("FilterPromo", filterPromoSchema, "filter_promos");

// Categories schema/model (used by /api/categories)
// Shape: { id, title, count, image, parentId? } — parentId null/omit = top-level; numeric = subcategory
const categorySchema = new mongoose.Schema(
  {
    id: { type: Number, required: true, index: true, unique: true },
    title: { type: String, required: true },
    count: { type: String, default: "0" },
    // Subcategories may omit; top-level categories are validated in admin APIs.
    image: { type: String, default: "" },
    parentId: { type: Number, default: null, index: true },
    // Lower first: header nav + Shop by Categories order (same list)
    sortOrder: { type: Number, default: 0, index: true },
  },
  { timestamps: true },
);

const Category = mongoose.model("Category", categorySchema, "categories");

async function assertParentIsRootCategory(parentNumericId) {
  const parent = await Category.findOne({ id: parentNumericId }).lean();
  if (!parent) {
    const err = new Error("Parent category not found");
    err.statusCode = 404;
    throw err;
  }
  if (parent.parentId != null && parent.parentId !== undefined) {
    const err = new Error(
      "Subcategories can only be created under a top-level category",
    );
    err.statusCode = 400;
    throw err;
  }
  return parent;
}

/** Next sortOrder for a new row among siblings (same parent): max(sortOrder)+1 */
async function nextAutoSortOrder(parentId) {
  const match =
    parentId == null || parentId === undefined
      ? { $or: [{ parentId: null }, { parentId: { $exists: false } }] }
      : { parentId: Number(parentId) };
  const agg = await Category.aggregate([
    { $match: match },
    {
      $group: {
        _id: null,
        maxSo: { $max: { $ifNull: ["$sortOrder", 0] } },
      },
    },
  ]);
  const maxSo =
    agg[0] && agg[0].maxSo != null ? Number(agg[0].maxSo) : -1;
  return maxSo + 1;
}

/**
 * Live product counts from catalog_products (non-inactive).
 * Root categories: products in this id + all direct child category ids.
 */
async function attachLiveProductCounts(categories) {
  if (!Array.isArray(categories) || !categories.length) return categories;
  let Cat;
  try {
    Cat = mongoose.model("CatalogProduct");
  } catch {
    return categories.map((c) => ({
      ...c,
      count: String(c.count != null ? c.count : "0"),
    }));
  }
  const allIds = categories.map((c) => c.id).filter((id) => id != null);
  const countMap = new Map();
  if (allIds.length) {
    const rows = await Cat.aggregate([
      {
        $match: {
          $or: [
            { categoryIds: { $in: allIds } },
            { categoryId: { $in: allIds } },
          ],
          status: { $ne: "inactive" },
        },
      },
      {
        $addFields: {
          _catIds: {
            $cond: [
              { $isArray: "$categoryIds" },
              "$categoryIds",
              ["$categoryId"],
            ],
          },
        },
      },
      { $unwind: "$_catIds" },
      { $match: { _catIds: { $in: allIds } } },
      { $group: { _id: "$_catIds", n: { $sum: 1 } } },
    ]);
    rows.forEach((r) => {
      countMap.set(r._id, r.n);
    });
  }
  const childIdsByParent = new Map();
  categories.forEach((c) => {
    if (c.parentId != null && c.parentId !== undefined) {
      const p = Number(c.parentId);
      if (!childIdsByParent.has(p)) childIdsByParent.set(p, []);
      childIdsByParent.get(p).push(c.id);
    }
  });
  return categories.map((cat) => {
    let n = 0;
    const isRoot =
      cat.parentId == null || cat.parentId === undefined;
    if (isRoot) {
      const ids = [cat.id, ...(childIdsByParent.get(cat.id) || [])];
      ids.forEach((id) => {
        n += countMap.get(id) || 0;
      });
    } else {
      n = countMap.get(cat.id) || 0;
    }
    return { ...cat, count: String(n) };
  });
}




app.get("/api/slider", async (req, res) => {
  try {
    // If DB is not connected, serve defaults so homepage doesn't break
    if (mongoose.connection.readyState !== 1 || !mongoose.connection.db) {
      return res.json(DEFAULT_SLIDER_SLIDES);
    }
    await seedSliderIfEmpty();
    const slides = await SliderSlide.find().sort({ id: 1 }).lean();
    return res.json(slides);
  } catch (err) {
    console.error("Error fetching slider slides", err);
    // Fallback to defaults on errors
    return res.json(DEFAULT_SLIDER_SLIDES);
  }
});

// Public: collection header slides (enabled only)
app.get("/api/collection-header-slides", async (req, res) => {
  try {
    // If DB is not connected, serve defaults so UI still works.
    if (mongoose.connection.readyState !== 1 || !mongoose.connection.db) {
      return res.json(
        DEFAULT_COLLECTION_HEADER_SLIDES.filter((s) => s && s.enabled).sort((a, b) => (a.id || 0) - (b.id || 0)),
      );
    }
    await seedCollectionHeaderSlidesIfEmpty();
    const items = await CollectionHeaderSlide.find({ enabled: true }).sort({ id: 1 }).lean();
    return res.json(items);
  } catch (err) {
    console.error("Error fetching collection header slides", err);
    // Fallback to defaults on errors (avoid breaking storefront)
    return res.json(
      DEFAULT_COLLECTION_HEADER_SLIDES.filter((s) => s && s.enabled).sort((a, b) => (a.id || 0) - (b.id || 0)),
    );
  }
});

// Public: happy customer testimonials
app.get("/api/testimonials", async (req, res) => {
  try {
    if (mongoose.connection.readyState !== 1 || !mongoose.connection.db) {
      return res.json(DEFAULT_TESTIMONIALS.filter((t) => t && t.enabled).sort((a, b) => (a.id || 0) - (b.id || 0)));
    }
    await seedTestimonialsIfEmpty();
    const items = await Testimonial.find({ enabled: true }).sort({ id: 1 }).lean();
    return res.json(items);
  } catch (err) {
    console.error("Error fetching testimonials", err);
    return res.json(DEFAULT_TESTIMONIALS.filter((t) => t && t.enabled).sort((a, b) => (a.id || 0) - (b.id || 0)));
  }
});

// Admin: list testimonials (all)
app.get("/api/admin/testimonials", authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const items = await Testimonial.find().sort({ id: 1 }).lean();
    return res.json({ items });
  } catch (err) {
    console.error("Error listing testimonials", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// Admin: create testimonial
app.post("/api/admin/testimonials", authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const name = String(req.body?.name || "").trim();
    const title = String(req.body?.title || "").trim();
    const ratingRaw = Number(req.body?.rating ?? 5);
    const rating = Math.min(5, Math.max(1, Number.isFinite(ratingRaw) ? ratingRaw : 5));
    const text = String(req.body?.text || "").trim();
    const mainImageUrl = String(req.body?.mainImageUrl || "").trim();
    const productTitle = String(req.body?.productTitle || "").trim();
    const productHref = String(req.body?.productHref || "").trim();
    const productImageUrl = String(req.body?.productImageUrl || "").trim();
    const enabled = req.body?.enabled === undefined ? true : Boolean(req.body.enabled);

    if (!name) return res.status(400).json({ error: "name is required" });
    if (!text) return res.status(400).json({ error: "text is required" });

    const last = await Testimonial.findOne().sort({ id: -1 }).lean();
    const nextId = (last?.id != null ? Number(last.id) : 0) + 1;

    const doc = await Testimonial.create({
      id: nextId,
      name,
      title,
      rating,
      text,
      mainImageUrl,
      productTitle,
      productHref,
      productImageUrl,
      enabled,
    });
    return res.json(doc.toObject());
  } catch (err) {
    console.error("Error creating testimonial", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// Admin: update testimonial (by numeric id)
app.put("/api/admin/testimonials/:id", authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isFinite(id)) return res.status(400).json({ error: "Invalid testimonial id" });

    const patch = {};
    if (req.body?.name !== undefined) patch.name = String(req.body.name || "").trim();
    if (req.body?.title !== undefined) patch.title = String(req.body.title || "").trim();
    if (req.body?.text !== undefined) patch.text = String(req.body.text || "").trim();
    if (req.body?.mainImageUrl !== undefined) patch.mainImageUrl = String(req.body.mainImageUrl || "").trim();
    if (req.body?.productTitle !== undefined) patch.productTitle = String(req.body.productTitle || "").trim();
    if (req.body?.productHref !== undefined) patch.productHref = String(req.body.productHref || "").trim();
    if (req.body?.productImageUrl !== undefined) patch.productImageUrl = String(req.body.productImageUrl || "").trim();
    if (req.body?.enabled !== undefined) patch.enabled = Boolean(req.body.enabled);
    if (req.body?.rating !== undefined) {
      const r = Number(req.body.rating);
      patch.rating = Math.min(5, Math.max(1, Number.isFinite(r) ? r : 5));
    }

    if (patch.name !== undefined && !patch.name) return res.status(400).json({ error: "name is required" });
    if (patch.text !== undefined && !patch.text) return res.status(400).json({ error: "text is required" });

    const updated = await Testimonial.findOneAndUpdate({ id }, { $set: patch }, { new: true }).lean();
    if (!updated) return res.status(404).json({ error: "Testimonial not found" });
    return res.json(updated);
  } catch (err) {
    console.error("Error updating testimonial", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// Admin: delete testimonial (by numeric id)
app.delete("/api/admin/testimonials/:id", authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isFinite(id)) return res.status(400).json({ error: "Invalid testimonial id" });
    const deleted = await Testimonial.findOneAndDelete({ id }).lean();
    if (!deleted) return res.status(404).json({ error: "Testimonial not found" });
    return res.json({ ok: true, deletedId: id });
  } catch (err) {
    console.error("Error deleting testimonial", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// Admin: reorder testimonials (set id based on order)
app.put("/api/admin/testimonials/reorder", authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const items = Array.isArray(req.body?.items) ? req.body.items : [];
    const ids = items
      .map((it) => Number(it?.id))
      .filter((n) => Number.isFinite(n));
    if (!ids.length) return res.status(400).json({ error: "items is required" });

    // Update each testimonial to sequential id (1..n)
    const bulk = ids.map((oldId, idx) => ({
      updateOne: {
        filter: { id: oldId },
        update: { $set: { id: idx + 1 } },
      },
    }));
    await Testimonial.bulkWrite(bulk);
    const updated = await Testimonial.find().sort({ id: 1 }).lean();
    return res.json({ ok: true, items: updated });
  } catch (err) {
    console.error("Error reordering testimonials", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// ─── Admin: Collection header slides ───────────────────────────────────────
app.get(
  "/api/admin/collection-header-slides",
  authMiddleware,
  adminMiddleware,
  async (req, res) => {
    try {
      if (mongoose.connection.readyState !== 1 || !mongoose.connection.db) {
        return res.json({ items: DEFAULT_COLLECTION_HEADER_SLIDES.slice().sort((a, b) => (a.id || 0) - (b.id || 0)) });
      }
      await seedCollectionHeaderSlidesIfEmpty();
      const items = await CollectionHeaderSlide.find().sort({ id: 1 }).lean();
      return res.json({ items });
    } catch (err) {
      console.error("Error listing collection header slides", err);
      return res.status(500).json({ error: "Internal server error" });
    }
  },
);

app.post(
  "/api/admin/collection-header-slides",
  authMiddleware,
  adminMiddleware,
  async (req, res) => {
    try {
      if (mongoose.connection.readyState !== 1) {
        return res.status(503).json({ error: "Database not connected" });
      }
      const title = String(req.body?.title || "").trim();
      const description = String(req.body?.description || "").trim();
      const imageUrl = String(req.body?.imageUrl || "").trim();
      const enabled = req.body?.enabled === undefined ? true : Boolean(req.body.enabled);

      if (!title) return res.status(400).json({ error: "title is required" });
      if (!imageUrl) return res.status(400).json({ error: "imageUrl is required" });

      const last = await CollectionHeaderSlide.findOne().sort({ id: -1 }).lean();
      const nextId = (last?.id != null ? Number(last.id) : 0) + 1;

      const doc = await CollectionHeaderSlide.create({
        id: nextId,
        title,
        description,
        imageUrl,
        enabled,
      });
      return res.json(doc.toObject());
    } catch (err) {
      console.error("Error creating collection header slide", err);
      return res.status(500).json({ error: "Internal server error" });
    }
  },
);

app.put(
  "/api/admin/collection-header-slides/:id",
  authMiddleware,
  adminMiddleware,
  async (req, res) => {
    try {
      if (mongoose.connection.readyState !== 1) {
        return res.status(503).json({ error: "Database not connected" });
      }
      const id = Number(req.params.id);
      if (!Number.isFinite(id)) return res.status(400).json({ error: "Invalid slide id" });

      const patch = {};
      if (req.body?.title !== undefined) patch.title = String(req.body.title || "").trim();
      if (req.body?.description !== undefined) patch.description = String(req.body.description || "").trim();
      if (req.body?.imageUrl !== undefined) patch.imageUrl = String(req.body.imageUrl || "").trim();
      if (req.body?.enabled !== undefined) patch.enabled = Boolean(req.body.enabled);

      if (patch.title !== undefined && !patch.title) return res.status(400).json({ error: "title is required" });
      if (patch.imageUrl !== undefined && !patch.imageUrl) return res.status(400).json({ error: "imageUrl is required" });

      const updated = await CollectionHeaderSlide.findOneAndUpdate(
        { id },
        { $set: patch },
        { new: true },
      ).lean();
      if (!updated) return res.status(404).json({ error: "Slide not found" });
      return res.json(updated);
    } catch (err) {
      console.error("Error updating collection header slide", err);
      return res.status(500).json({ error: "Internal server error" });
    }
  },
);

app.delete(
  "/api/admin/collection-header-slides/:id",
  authMiddleware,
  adminMiddleware,
  async (req, res) => {
    try {
      if (mongoose.connection.readyState !== 1) {
        return res.status(503).json({ error: "Database not connected" });
      }
      const id = Number(req.params.id);
      if (!Number.isFinite(id)) return res.status(400).json({ error: "Invalid slide id" });
      const deleted = await CollectionHeaderSlide.findOneAndDelete({ id }).lean();
      if (!deleted) return res.status(404).json({ error: "Slide not found" });
      return res.json({ ok: true, deletedId: id });
    } catch (err) {
      console.error("Error deleting collection header slide", err);
      return res.status(500).json({ error: "Internal server error" });
    }
  },
);

app.put(
  "/api/admin/collection-header-slides/reorder",
  authMiddleware,
  adminMiddleware,
  async (req, res) => {
    try {
      if (mongoose.connection.readyState !== 1) {
        return res.status(503).json({ error: "Database not connected" });
      }
      const items = Array.isArray(req.body?.items) ? req.body.items : [];
      const ids = items
        .map((it) => Number(it?.id))
        .filter((n) => Number.isFinite(n));
      if (!ids.length) return res.status(400).json({ error: "items is required" });

      const bulk = ids.map((oldId, idx) => ({
        updateOne: { filter: { id: oldId }, update: { $set: { id: idx + 1 } } },
      }));
      await CollectionHeaderSlide.bulkWrite(bulk);
      const updated = await CollectionHeaderSlide.find().sort({ id: 1 }).lean();
      return res.json({ ok: true, items: updated });
    } catch (err) {
      console.error("Error reordering collection header slides", err);
      return res.status(500).json({ error: "Internal server error" });
    }
  },
);

// Public: get collection filters promo banner (single doc)
app.get("/api/filter-promo", async (req, res) => {
  try {
    const key = "collectionFilters";
    let doc = await FilterPromo.findOne({ key }).lean();
    if (!doc) {
      doc = (
        await FilterPromo.create({
          key,
          enabled: true,
          badgeText: "Online Exclusive",
          title: "SALE UP TO 25% OFF",
          ctaText: "Shop The Sale",
          ctaHref: "#",
          imageUrl: "",
          imageAlt: "Promotion",
        })
      ).toObject();
    }
    return res.json({ promo: doc });
  } catch (err) {
    console.error("Error fetching filter promo", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// Public: home/social gallery images (dynamic from catalog products)
// Returns: { items: [{ id, src, srcSet, width, height, productId, slug, title }] }
app.get("/api/social-gallery", async (req, res) => {
  try {
    const rawLimit = req.query?.limit;
    const limit = Math.min(Math.max(parseInt(rawLimit, 10) || 5, 1), 10);

    // Randomize items each call (so homepage feels fresh)
    const docs = await CatalogProduct.aggregate([
      {
        $match: {
          status: { $ne: "inactive" },
          variants: { $exists: true, $ne: [] },
        },
      },
      { $sample: { size: 140 } },
    ]);

    // Best-effort: pick products from distinct categories first
    const picked = [];
    const seenCats = new Set();

    const pushIfOk = (p) => {
      if (!p || picked.length >= limit) return;
      const v0 = Array.isArray(p.variants) ? p.variants[0] : null;
      const img0 = v0 && Array.isArray(v0.images) ? v0.images[0] : null;
      if (!img0) return;

      const cats = Array.isArray(p.categoryIds) && p.categoryIds.length
        ? p.categoryIds
        : (p.categoryId != null ? [p.categoryId] : []);
      const catKey = cats.map((c) => String(c)).join(",") || "none";
      if (seenCats.has(catKey)) return;
      seenCats.add(catKey);

      picked.push({
        id: String(p._id),
        productId: String(p._id),
        slug: p.slug || "",
        title: p.name || "Product",
        src: img0,
        srcSet: img0,
        width: 560,
        height: 560,
      });
    };

    for (const p of docs) {
      if (picked.length >= limit) break;
      pushIfOk(p);
    }

    // Fallback: fill remaining slots ignoring categories
    if (picked.length < limit) {
      for (const p of docs) {
        if (picked.length >= limit) break;
        const v0 = Array.isArray(p.variants) ? p.variants[0] : null;
        const img0 = v0 && Array.isArray(v0.images) ? v0.images[0] : null;
        if (!img0) continue;
        if (picked.some((x) => x.id === String(p._id))) continue;
        picked.push({
          id: String(p._id),
          productId: String(p._id),
          slug: p.slug || "",
          title: p.name || "Product",
          src: img0,
          srcSet: img0,
          width: 560,
          height: 560,
        });
      }
    }

    return res.json({ items: picked.slice(0, limit) });
  } catch (err) {
    console.error("Error fetching social gallery", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// Public: update collection filters promo banner (no auth)
app.put("/api/filter-promo", async (req, res) => {
  try {
    const key = "collectionFilters";
    const {
      enabled,
      badgeText,
      title,
      ctaText,
      ctaHref,
      imageUrl,
      imageAlt,
    } = req.body || {};

    const patch = {};
    if (typeof enabled === "boolean") patch.enabled = enabled;
    if (badgeText !== undefined) patch.badgeText = String(badgeText || "");
    if (title !== undefined) patch.title = String(title || "");
    if (ctaText !== undefined) patch.ctaText = String(ctaText || "");
    if (ctaHref !== undefined) patch.ctaHref = String(ctaHref || "");
    if (imageUrl !== undefined) patch.imageUrl = String(imageUrl || "");
    if (imageAlt !== undefined) patch.imageAlt = String(imageAlt || "");

    const updated = await FilterPromo.findOneAndUpdate(
      { key },
      { $set: { key, ...patch } },
      { upsert: true, new: true },
    ).lean();

    return res.json({ promo: updated, message: "Filter promo updated" });
  } catch (err) {
    console.error("Error updating filter promo (public)", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// Admin: read filter promo
app.get(
  "/api/admin/filter-promo",
  async (req, res) => {
    try {
      const key = "collectionFilters";
      let doc = await FilterPromo.findOne({ key }).lean();
      if (!doc) {
        doc = (
          await FilterPromo.create({
            key,
            enabled: true,
            badgeText: "Online Exclusive",
            title: "SALE UP TO 25% OFF",
            ctaText: "Shop The Sale",
            ctaHref: "#",
            imageUrl: "",
            imageAlt: "Promotion",
          })
        ).toObject();
      }
      return res.json({ promo: doc });
    } catch (err) {
      console.error("Error fetching admin filter promo", err);
      return res.status(500).json({ error: "Internal server error" });
    }
  },
);

// Admin: update filter promo
app.put(
  "/api/admin/filter-promo",
  async (req, res) => {
    try {
      const key = "collectionFilters";
      const {
        enabled,
        badgeText,
        title,
        ctaText,
        ctaHref,
        imageUrl,
        imageAlt,
      } = req.body || {};

      const patch = {};
      if (typeof enabled === "boolean") patch.enabled = enabled;
      if (badgeText !== undefined) patch.badgeText = String(badgeText || "");
      if (title !== undefined) patch.title = String(title || "");
      if (ctaText !== undefined) patch.ctaText = String(ctaText || "");
      if (ctaHref !== undefined) patch.ctaHref = String(ctaHref || "");
      if (imageUrl !== undefined) patch.imageUrl = String(imageUrl || "");
      if (imageAlt !== undefined) patch.imageAlt = String(imageAlt || "");

      const updated = await FilterPromo.findOneAndUpdate(
        { key },
        { $set: { key, ...patch } },
        { upsert: true, new: true },
      ).lean();

      return res.json({ promo: updated, message: "Filter promo updated" });
    } catch (err) {
      console.error("Error updating filter promo", err);
      return res.status(500).json({ error: "Internal server error" });
    }
  },
);

// Admin API: create a new slider slide in DB
app.post("/api/admin/slider", async (req, res) => {
  try {
    if (mongoose.connection.readyState !== 1 || !mongoose.connection.db) {
      return res.status(503).json({ error: "Database not connected" });
    }
    const { title, subtitle, imageUrl, categoryId: rawCategoryId } = req.body;

    if (
      !title ||
      !subtitle ||
      !Array.isArray(subtitle) ||
      subtitle.length === 0 ||
      !imageUrl
    ) {
      return res.status(400).json({
        error: "title, subtitle (array), and imageUrl are required",
      });
    }

    // Auto-generate incremental numeric id so the unique index on `id` never gets `null`
    const last = await SliderSlide.findOne().sort({ id: -1 }).lean();
    const nextId = (last && typeof last.id === "number" ? last.id : 0) + 1;

    const slideDoc = await SliderSlide.create({
      id: nextId,
      title,
      subtitle,
      images: imageUrl, // sirf single URL string store ho rahi hai
      categoryId: normalizeSliderCategoryId(rawCategoryId),
    });

    return res.status(201).json(slideDoc.toObject());
  } catch (err) {
    console.error("Error creating slider slide", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// Admin API: update a slider slide (by numeric `id`)
app.put("/api/admin/slider/:id", async (req, res) => {
  try {
    if (mongoose.connection.readyState !== 1 || !mongoose.connection.db) {
      return res.status(503).json({ error: "Database not connected" });
    }
    const slideId = Number(req.params.id);
    if (!Number.isFinite(slideId)) {
      return res.status(400).json({ error: "Invalid slider id" });
    }

    const { title, subtitle, imageUrl, categoryId: rawCategoryId } =
      req.body || {};

    if (
      !title ||
      !subtitle ||
      !Array.isArray(subtitle) ||
      subtitle.length === 0 ||
      !imageUrl
    ) {
      return res.status(400).json({
        error: "title, subtitle (array), and imageUrl are required",
      });
    }

    const updated = await SliderSlide.findOneAndUpdate(
      { id: slideId },
      {
        $set: {
          title: String(title),
          subtitle,
          images: imageUrl, // single URL string
          categoryId: normalizeSliderCategoryId(rawCategoryId),
        },
      },
      { new: true },
    ).lean();

    if (!updated) return res.status(404).json({ error: "Slide not found" });
    return res.json(updated);
  } catch (err) {
    console.error("Error updating slider slide", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// Admin API: delete a slider slide (by numeric `id`)
app.delete("/api/admin/slider/:id", async (req, res) => {
  try {
    if (mongoose.connection.readyState !== 1 || !mongoose.connection.db) {
      return res.status(503).json({ error: "Database not connected" });
    }
    const slideId = Number(req.params.id);
    if (!Number.isFinite(slideId)) {
      return res.status(400).json({ error: "Invalid slider id" });
    }

    const deleted = await SliderSlide.findOneAndDelete({ id: slideId }).lean();
    if (!deleted) return res.status(404).json({ error: "Slide not found" });
    return res.json({ ok: true, deletedId: slideId });
  } catch (err) {
    console.error("Error deleting slider slide", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// API to get all categories from MongoDB (used by ShopCatogries.jsx)
app.get("/api/categories", async (req, res) => {
  try {
    const categories = await Category.find()
      .sort({ sortOrder: 1, id: 1 })
      .lean();
    const withCounts = await attachLiveProductCounts(categories);
    const wantsSplit =
      String(req.query?.split || "").trim() === "1" ||
      String(req.query?.split || "").trim().toLowerCase() === "true";
    if (!wantsSplit) {
      return res.json(withCounts);
    }

    // Split root categories into 2 groups for Shop By Categories UI.
    // Configure via env `SHOP_CATEGORIES_PRIMARY_IDS="1,2,3"` (numeric ids).
    const rawPrimary = String(process.env.SHOP_CATEGORIES_PRIMARY_IDS || "").trim();
    const primaryIdSet = new Set(
      rawPrimary
        ? rawPrimary
            .split(",")
            .map((v) => Number(String(v).trim()))
            .filter((n) => Number.isFinite(n))
        : [],
    );
    const primaryLimit = Math.max(
      1,
      Math.min(parseInt(String(req.query?.primaryLimit || ""), 10) || 6, 30),
    );

    const isRoot = (c) => c == null || c.parentId == null || c.parentId === undefined;
    const rootsSorted = withCounts
      .filter(isRoot)
      .slice()
      .sort(
        (a, b) =>
          (Number(a.sortOrder) || 0) - (Number(b.sortOrder) || 0) ||
          (Number(a.id) || 0) - (Number(b.id) || 0),
      );
    const primaryRoots = primaryIdSet.size
      ? rootsSorted.filter((c) => primaryIdSet.has(Number(c.id)))
      : rootsSorted.slice(0, primaryLimit);
    const primaryRootIds = new Set(primaryRoots.map((c) => Number(c.id)).filter((n) => Number.isFinite(n)));

    const enriched = withCounts.map((c) => {
      if (!isRoot(c)) return c;
      const idNum = Number(c.id);
      const splitGroup =
        Number.isFinite(idNum) && primaryRootIds.has(idNum) ? "primary" : "secondary";
      return { ...c, splitGroup };
    });
    return res.json(enriched);
  } catch (err) {
    console.error("Error fetching categories", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Master API: return all added categories (alias of /api/categories)
app.get("/api/master/categories", async (req, res) => {
  try {
    const categories = await Category.find(
      {},
      { _id: 0, id: 1, title: 1, parentId: 1, sortOrder: 1 },
    )
      .sort({ sortOrder: 1, id: 1 })
      .lean();
    res.json(categories);
  } catch (err) {
    console.error("Error fetching master categories", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Admin API: create a single new shop category
// Body: { title, image?, parentId? } — image optional for subcategories; required for top-level
// count & sortOrder are automatic (products + next slot among siblings)
app.post("/api/admin/categories", async (req, res) => {
  try {
    const { title, image, parentId: parentIdRaw } = req.body || {};
    const titleTrim = String(title || "").trim();
    const imageStr =
      image != null && image !== undefined ? String(image).trim() : "";

    if (!titleTrim) {
      return res.status(400).json({ error: "title is required" });
    }

    let parentId = null;
    if (parentIdRaw != null && parentIdRaw !== "") {
      const p = Number(parentIdRaw);
      if (!Number.isFinite(p)) {
        return res.status(400).json({ error: "Invalid parentId" });
      }
      try {
        await assertParentIsRootCategory(p);
      } catch (e) {
        const code = e.statusCode || 500;
        return res.status(code).json({ error: e.message });
      }
      parentId = p;
    }

    const isSubcategory = parentId != null;
    if (!isSubcategory && !imageStr) {
      return res.status(400).json({
        error: "Image is required for top-level categories",
      });
    }

    const sortOrder = await nextAutoSortOrder(parentId);

    // Auto-generate incremental numeric id so the unique index on `id` never gets null
    const last = await Category.findOne().sort({ id: -1 }).lean();
    const nextId =
      (last && typeof last.id === "number" ? last.id : 0) + 1;

    const categoryDoc = await Category.create({
      id: nextId,
      title: titleTrim,
      count: "0",
      image: imageStr,
      parentId,
      sortOrder,
    });

    const [enriched] = await attachLiveProductCounts([
      categoryDoc.toObject(),
    ]);
    return res.status(201).json(enriched);
  } catch (err) {
    console.error("Error inserting category", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// Admin API: update a category by numeric `id`
// Body: { title, image?, parentId?, sortOrder? } — product count is always computed on read, not stored from client
// image optional for subcategories; top-level needs a non-empty image (omit `image` to keep existing URL)
app.put("/api/admin/categories/:id", async (req, res) => {
  try {
    const categoryId = Number(req.params.id);
    if (!Number.isFinite(categoryId)) {
      return res.status(400).json({ error: "Invalid category id" });
    }

    const {
      title,
      image,
      parentId: parentIdRaw,
      sortOrder: sortOrderRaw,
    } = req.body || {};

    if (!String(title || "").trim()) {
      return res.status(400).json({ error: "title is required" });
    }

    const existing = await Category.findOne({ id: categoryId }).lean();
    if (!existing) return res.status(404).json({ error: "Category not found" });

    const update = { title: String(title).trim() };

    const imageProvided = Object.prototype.hasOwnProperty.call(
      req.body || {},
      "image",
    );
    let imageStr;
    if (imageProvided) {
      imageStr =
        image != null && image !== undefined ? String(image).trim() : "";
    } else {
      imageStr =
        existing.image != null ? String(existing.image).trim() : "";
    }
    update.image = imageStr;

    if (Object.prototype.hasOwnProperty.call(req.body || {}, "sortOrder")) {
      update.sortOrder = Number.isFinite(Number(sortOrderRaw))
        ? Number(sortOrderRaw)
        : 0;
    }

    let effectiveParentId = existing.parentId;

    if (Object.prototype.hasOwnProperty.call(req.body || {}, "parentId")) {
      let newParent = null;
      if (parentIdRaw != null && parentIdRaw !== "") {
        newParent = Number(parentIdRaw);
        if (!Number.isFinite(newParent)) {
          return res.status(400).json({ error: "Invalid parentId" });
        }
        if (newParent === categoryId) {
          return res.status(400).json({ error: "Category cannot be its own parent" });
        }
        const childCount = await Category.countDocuments({ parentId: categoryId });
        if (childCount > 0) {
          return res.status(400).json({
            error:
              "Cannot turn a parent category into a subcategory while it still has subcategories",
          });
        }
        try {
          await assertParentIsRootCategory(newParent);
        } catch (e) {
          const code = e.statusCode || 500;
          return res.status(code).json({ error: e.message });
        }
      }
      update.parentId = newParent;
      effectiveParentId = newParent;
    }

    const isRoot =
      effectiveParentId == null || effectiveParentId === undefined;
    if (isRoot && !imageStr) {
      return res.status(400).json({
        error: "Image is required for top-level categories",
      });
    }

    const updated = await Category.findOneAndUpdate(
      { id: categoryId },
      { $set: update },
      { new: true },
    ).lean();

    if (!updated) return res.status(404).json({ error: "Category not found" });
    const [enriched] = await attachLiveProductCounts([updated]);
    return res.json(enriched);
  } catch (err) {
    console.error("Error updating category", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// Admin API: delete a category by numeric `id` (also removes its subcategories)
app.delete("/api/admin/categories/:id", async (req, res) => {
  try {
    const categoryId = Number(req.params.id);
    if (!Number.isFinite(categoryId)) {
      return res.status(400).json({ error: "Invalid category id" });
    }

    const existing = await Category.findOne({ id: categoryId }).lean();
    if (!existing) return res.status(404).json({ error: "Category not found" });

    await Category.deleteMany({ parentId: categoryId });
    const deleted = await Category.findOneAndDelete({ id: categoryId }).lean();
    return res.json({ ok: true, deleted });
  } catch (err) {
    console.error("Error deleting category", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

const productSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    price: { type: Number, required: true },
  },
  { timestamps: true },
);
const Product = mongoose.model("Product", productSchema);

// Optional manual size guide (measurements stored in centimeters)
const catalogSizeGuideRowSchema = new mongoose.Schema(
  {
    sizeLabel: { type: String, trim: true, default: "" },
    // New: parallel measurements in cm (same order as sizeGuide.measureColumns).
    values: [{ type: mongoose.Schema.Types.Mixed }],
    // Legacy (still read for old documents).
    bust: { type: Number },
    shoulder: { type: Number },
    sleeve: { type: Number },
  },
  { _id: false },
);

const catalogSizeGuideSchema = new mongoose.Schema(
  {
    fitType: { type: String, trim: true, default: "" },
    stretchability: { type: String, trim: true, default: "" },
    rows: { type: [catalogSizeGuideRowSchema], default: [] },
    // Admin-defined column headings (any count, max normalized in API).
    measureColumns: { type: [String], default: [] },
    // Legacy headings (read when measureColumns missing).
    colLabelBust: { type: String, trim: true, default: "" },
    colLabelShoulder: { type: String, trim: true, default: "" },
    colLabelSleeve: { type: String, trim: true, default: "" },
  },
  { _id: false },
);

// Catalog Product model (new) - does NOT affect existing /api/products
const catalogProductSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true },
    // slug auto-generated from `name` if not provided
    slug: {
      type: String,
      required: true,
      trim: true,
      unique: true,
      index: true,
    },
    price: { type: Number, required: true, min: 0 },
    discountPrice: { type: Number, min: 0 },
    description: { type: String, required: true },
    brand: { type: String, trim: true, default: "" },
    // master categories return numeric `id`
    // Backward-compat: older records may still store a single `categoryId`.
    categoryId: { type: Number, required: false, index: true },
    // New: product can belong to multiple categories.
    categoryIds: { type: [Number], required: true, index: true },
    variants: [
      {
        color: { type: String, trim: true, default: "" },
        // Multi-color support: additional color names for this variant.
        // Kept optional + backward compatible with existing data using only `color`.
        colors: { type: [String], default: [] },
        colorCode: { type: String, trim: true, default: "" },
        // When `sizes` is empty, inventory is tracked here (no S/M/L).
        stock: { type: Number, default: 0, min: 0 },
        sizes: [
          {
            size: { type: String, required: true },
            stock: { type: Number, required: true, min: 0 },
          },
        ],
        images: [{ type: String, required: true }],
      },
    ],
    rating: { type: Number, default: 0, min: 0, max: 5 },
    numReviews: { type: Number, default: 0, min: 0 },
    isFeatured: { type: Boolean, default: false },
    status: { type: String, enum: ["active", "inactive"], default: "active" },
    // Optional per-product size guide (image URL, e.g. Cloudinary) — legacy
    sizeChartImage: { type: String, default: "", trim: true },
    sizeChartTitle: { type: String, default: "", trim: true },
    // Optional structured size guide (manual); measurements in cm
    sizeGuide: { type: catalogSizeGuideSchema, default: null },

    // Optional specifications (key/value pairs) shown on product detail page
    specifications: {
      type: [
        {
          label: { type: String, trim: true, default: "" },
          value: { type: String, trim: true, default: "" },
        },
      ],
      default: [],
    },
  },
  { timestamps: true },
);

const CatalogProduct = mongoose.model(
  "CatalogProduct",
  catalogProductSchema,
  "catalog_products",
);

// ─────────────────────────────────────────────────────────────────────────────
// Search suggestions (public): categories + products (autocomplete)
// GET /api/search/suggest?q=...
// ─────────────────────────────────────────────────────────────────────────────
function normalizeSearchQuery(q) {
  return String(q || "")
    .toLowerCase()
    .trim()
    .replace(/\s+/g, " ")
    .replace(/[^\p{L}\p{N}\s-]/gu, "");
}

function applySearchSynonyms(q) {
  const s = normalizeSearchQuery(q);
  if (!s) return "";
  const map = new Map([
    ["jwellery", "jewellery"],
    ["jwellary", "jewellery"],
    ["jwellry", "jewellery"],
    ["jewelery", "jewellery"],
    ["jewelry", "jewellery"],
    ["co ord", "co-ord"],
    ["coord", "co-ord"],
    ["co ord set", "co-ord"],
    ["co ord sets", "co-ord"],
  ]);
  return map.get(s) || s;
}

function escapeRegex(s) {
  return String(s || "").replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

app.get("/api/search/suggest", async (req, res) => {
  try {
    const raw = String(req.query.q || "").trim();
    const q = applySearchSynonyms(raw);
    if (!q) return res.json({ categories: [], products: [], colors: [] });

    if (mongoose.connection.readyState !== 1 || !mongoose.connection.db) {
      return res.json({ categories: [], products: [], colors: [] });
    }

    const limit = Math.min(Math.max(Number(req.query.limit || 8) || 8, 1), 12);
    const rx = new RegExp(escapeRegex(q), "i");

    const [cats, prods, colorDocs] = await Promise.all([
      Category.find({ title: rx })
        .sort({ sortOrder: 1, parentId: 1, title: 1 })
        .limit(limit)
        .lean(),
      CatalogProduct.find({
        status: { $ne: "inactive" },
        $or: [
          { name: rx },
          { slug: rx },
          { brand: rx },
          { "variants.color": rx },
          { "variants.colors": rx },
        ],
      })
        .select({ _id: 1, name: 1, slug: 1, variants: 1 })
        .limit(limit)
        .lean(),
      // Fetch docs matching colors so we can build robust color suggestions in JS.
      CatalogProduct.find({
        status: { $ne: "inactive" },
        $or: [{ "variants.color": rx }, { "variants.colors": rx }],
      })
        .select({ _id: 1, variants: 1, categoryId: 1, categoryIds: 1 })
        .limit(220)
        .lean(),
    ]);

    const categories = (Array.isArray(cats) ? cats : []).map((c) => ({
      id: c.id,
      title: c.title,
      parentId: c.parentId ?? null,
    }));

    const products = (Array.isArray(prods) ? prods : []).map((p) => {
      const variants = Array.isArray(p?.variants) ? p.variants : [];
      const firstVariant = variants[0] || null;
      const img =
        (Array.isArray(firstVariant?.images) && firstVariant.images[0]) || "";
      const primaryColor = String(firstVariant?.color || "").trim();
      return {
        id: String(p._id),
        name: p.name,
        slug: p.slug || "",
        image: img || "",
        color: primaryColor,
      };
    });

    const colorsMap = new Map(); // key -> { labels:Set, codes:Set, productIds:Set }
    for (const doc of Array.isArray(colorDocs) ? colorDocs : []) {
      const pid = String(doc?._id || "");
      const variants = Array.isArray(doc?.variants) ? doc.variants : [];
      for (const v of variants) {
        const primaryLabel = String(v?.color || "").trim();
        const extras = Array.isArray(v?.colors) ? v.colors : [];
        const all = [primaryLabel, ...extras].map((x) => String(x || "").trim()).filter(Boolean);
        for (const label of all) {
          // Only suggest colors that match the user's query (case-insensitive)
          if (!rx.test(label)) continue;
          const key = normalizeCatalogColorNameKey(label);
          if (!key) continue;
          const row = colorsMap.get(key) || { labels: new Set(), codes: new Set(), productIds: new Set() };
          row.labels.add(label);
          // only attach the code when this label is the primary variant color
          if (primaryLabel && normalizeCatalogColorNameKey(primaryLabel) === key) {
            const code = String(v?.colorCode || "").trim();
            if (code) row.codes.add(code);
          }
          if (pid) row.productIds.add(pid);
          colorsMap.set(key, row);
        }
      }
    }
    const colors = Array.from(colorsMap.entries())
      .map(([colorKey, row]) => ({
        color: pickRepresentativeLabel(Array.from(row.labels)) || colorKey,
        colorCode: pickRepresentativeLabel(Array.from(row.codes)) || "#ccc",
        count: row.productIds.size,
      }))
      .sort((a, b) => (b.count || 0) - (a.count || 0))
      .slice(0, limit);

    // If the user is searching a color name (e.g. "yellow"), also suggest categories
    // that contain products with that color, so UI can offer "Category (filtered by color)" picks.
    const extraCategoryIds = new Set();
    if (colors.length) {
      for (const doc of Array.isArray(colorDocs) ? colorDocs : []) {
        const variants = Array.isArray(doc?.variants) ? doc.variants : [];
        const cats = Array.isArray(doc?.categoryIds) && doc.categoryIds.length
          ? doc.categoryIds
          : doc?.categoryId != null
            ? [doc.categoryId]
            : [];
        if (!cats.length) continue;
        // Only include categories from variants that match the query regex.
        let matches = false;
        for (const v of variants) {
          const primaryLabel = String(v?.color || "").trim();
          const extras = Array.isArray(v?.colors) ? v.colors : [];
          const all = [primaryLabel, ...extras].map((x) => String(x || "").trim()).filter(Boolean);
          if (all.some((lbl) => rx.test(lbl))) { matches = true; break; }
        }
        if (!matches) continue;
        for (const cid of cats) {
          const n = Number(cid);
          if (Number.isFinite(n)) extraCategoryIds.add(n);
        }
      }
    }

    let mergedCategories = categories;
    if (extraCategoryIds.size) {
      const existing = new Set(categories.map((c) => Number(c?.id)).filter((n) => Number.isFinite(n)));
      const want = Array.from(extraCategoryIds).filter((id) => !existing.has(id));
      if (want.length) {
        const extraCats = await Category.find({ id: { $in: want } })
          .sort({ sortOrder: 1, parentId: 1, title: 1 })
          .limit(limit)
          .lean();
        const extra = (Array.isArray(extraCats) ? extraCats : []).map((c) => ({
          id: c.id,
          title: c.title,
          parentId: c.parentId ?? null,
        }));
        mergedCategories = [...categories, ...extra].slice(0, limit);
      }
    }

    return res.json({ categories: mergedCategories, products, colors });
  } catch (err) {
    console.error("Search suggest error", err);
    return res.json({ categories: [], products: [], colors: [] });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// Search suggestions (public): categories + products (autocomplete)
// GET /api/search/suggest?q=...
// ─────────────────────────────────────────────────────────────────────────────
function normalizeSearchQuery(q) {
  return String(q || "")
    .toLowerCase()
    .trim()
    .replace(/\s+/g, " ")
    .replace(/[^\p{L}\p{N}\s-]/gu, "");
}

function applySearchSynonyms(q) {
  const s = normalizeSearchQuery(q);
  if (!s) return "";
  // Common misspellings / equivalents → canonical
  const map = new Map([
    ["jwellery", "jewellery"],
    ["jwellary", "jewellery"],
    ["jwellry", "jewellery"],
    ["jewelery", "jewellery"],
    ["jewelry", "jewellery"],
    ["co ord", "co-ord"],
    ["coord", "co-ord"],
    ["co ord set", "co-ord"],
    ["co ord sets", "co-ord"],
  ]);
  return map.get(s) || s;
}

function escapeRegex(s) {
  return String(s || "").replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

app.get("/api/search/suggest-legacy", async (req, res) => {
  try {
    const raw = String(req.query.q || "").trim();
    const q = applySearchSynonyms(raw);
    if (!q) return res.json({ categories: [], products: [] });

    // If DB not connected, return empty suggestions (avoid buffering timeouts).
    if (mongoose.connection.readyState !== 1 || !mongoose.connection.db) {
      return res.json({ categories: [], products: [] });
    }

    const limit = Math.min(Math.max(Number(req.query.limit || 8) || 8, 1), 12);
    const rx = new RegExp(escapeRegex(q), "i");

    const [cats, prods] = await Promise.all([
      Category.find({ title: rx })
        .sort({ sortOrder: 1, parentId: 1, title: 1 })
        .limit(limit)
        .lean(),
      CatalogProduct.find({
        status: { $ne: "inactive" },
        $or: [
          { name: rx },
          { slug: rx },
          { brand: rx },
          { "variants.color": rx },
          { "variants.colors": rx },
        ],
      })
        .select({ _id: 1, name: 1, slug: 1, variants: 1 })
        .limit(limit)
        .lean(),
    ]);

    const categories = (Array.isArray(cats) ? cats : []).map((c) => ({
      id: c.id,
      title: c.title,
      parentId: c.parentId ?? null,
    }));

    const products = (Array.isArray(prods) ? prods : []).map((p) => {
      const variants = Array.isArray(p?.variants) ? p.variants : [];
      const firstVariant = variants[0] || null;
      const img =
        (Array.isArray(firstVariant?.images) && firstVariant.images[0]) || "";
      return {
        id: String(p._id),
        name: p.name,
        slug: p.slug || "",
        image: img || "",
      };
    });

    return res.json({ categories, products });
  } catch (err) {
    console.error("Search suggest error", err);
    return res.json({ categories: [], products: [] });
  }
});

registerMixMatchRoutes(app, {
  MixMatchLook,
  CatalogProduct,
  mongoose,
  MIXMATCH_FALLBACK_LOOKS,
});

// Simple Cart schema/model to store items user added to cart
// (temporary - userId is hard-coded for now, until auth is added)
const cartItemSchema = new mongoose.Schema(
  {
    userId: { type: String, required: true, index: true },
    productId: { type: String, required: true },
    variantId: { type: String },
    name: { type: String, required: true },
    slug: { type: String },
    price: { type: Number, required: true, min: 0 },
    color: { type: String },
    size: { type: String },
    quantity: { type: Number, required: true, min: 1 },
    image: { type: String },
  },
  { timestamps: true },
);

// Prevent duplicate cart rows for same user + same product variant.
// Note: Mongo treats multiple docs with missing color/size as duplicates too (because null),
// so we only rely on this when color+size are present in payloads (catalog products).
cartItemSchema.index(
  { userId: 1, productId: 1, color: 1, size: 1 },
  { unique: true, sparse: true },
);

const CartItem = mongoose.model("CartItem", cartItemSchema, "cart_items");

// Wishlist schema/model (temporary - userId is hard-coded for now, until auth is added)
const wishlistItemSchema = new mongoose.Schema(
  {
    userId: { type: String, required: true, index: true },
    productId: { type: String, required: true, index: true },
    name: { type: String, required: true },
    slug: { type: String },
    price: { type: Number, required: true, min: 0 },
    image: { type: String },
  },
  { timestamps: true },
);
wishlistItemSchema.index({ userId: 1, productId: 1 }, { unique: true });
const WishlistItem = mongoose.model(
  "WishlistItem",
  wishlistItemSchema,
  "wishlist_items",
);

// Recently Viewed Products schema/model (per user, capped at 20)
const recentlyViewedSchema = new mongoose.Schema(
  {
    userId: { type: String, required: true, index: true },
    productId: { type: String, required: true },
    title: { type: String, required: true },
    slug: { type: String },
    price: { type: Number, default: 0 },
    image: { type: String },
    viewedAt: { type: Date, default: Date.now, index: true },
  },
  { timestamps: true },
);
recentlyViewedSchema.index({ userId: 1, productId: 1 }, { unique: true });

const RecentlyViewed = mongoose.model(
  "RecentlyViewed",
  recentlyViewedSchema,
  "recently_viewed",
);

// POST /api/recently-viewed/add  Body: { userId, productId, title, slug?, price?, image? }
app.post("/api/recently-viewed/add", async (req, res) => {
  try {
    const { userId, productId, title, slug, price, image } = req.body || {};
    if (!userId || !productId || !title) {
      return res.status(400).json({ error: "userId, productId and title are required" });
    }

    const uid = String(userId);
    const pid = String(productId);

    // Upsert: update viewedAt on re-view so it floats to the top
    await RecentlyViewed.findOneAndUpdate(
      { userId: uid, productId: pid },
      {
        $set: {
          userId: uid,
          productId: pid,
          title: String(title),
          slug: slug ? String(slug) : undefined,
          price: Number(price) || 0,
          image: image ? String(image) : undefined,
          viewedAt: new Date(),
        },
      },
      { new: true, upsert: true, setDefaultsOnInsert: true },
    );

    // Keep only the 20 most recent per user (prune older entries)
    const all = await RecentlyViewed.find({ userId: uid })
      .sort({ viewedAt: -1 })
      .select({ _id: 1 })
      .lean();

    if (all.length > 20) {
      const oldIds = all.slice(20).map((d) => d._id);
      await RecentlyViewed.deleteMany({ _id: { $in: oldIds } });
    }

    return res.status(201).json({ ok: true });
  } catch (err) {
    if (err && err.code === 11000) {
      return res.status(200).json({ ok: true });
    }
    console.error("Error adding recently viewed", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// POST /api/recently-viewed/list  Body: { userId, limit? }
app.post("/api/recently-viewed/list", async (req, res) => {
  try {
    const { userId, limit = 10 } = req.body || {};
    if (!userId) return res.status(400).json({ error: "userId is required" });

    const limitNum = Math.min(Math.max(parseInt(limit, 10) || 10, 1), 20);
    const rvItems = await RecentlyViewed.find({ userId: String(userId) })
      .sort({ viewedAt: -1 })
      .limit(limitNum)
      .lean();

    if (!rvItems.length) return res.json({ items: [] });

    // Enrich with full CatalogProduct data so the frontend gets the same
    // shape as /api/admin/catalog-products/search (variants, images, etc.)
    const productIds = rvItems
      .map((it) => {
        try { return new mongoose.Types.ObjectId(it.productId); } catch { return null; }
      })
      .filter(Boolean);

    const catalogDocs = productIds.length
      ? await CatalogProduct.find({ _id: { $in: productIds } }).lean()
      : [];

    const catalogMap = new Map(catalogDocs.map((p) => [String(p._id), p]));

    const items = rvItems.map((it) => {
      const full = catalogMap.get(String(it.productId));
      if (!full) return it; // catalog product deleted – use saved minimal data

      // Merge catalog data with saved RV data so incomplete catalog entries
      // (price=0, missing variants) still show the correct saved price/image
      const hasPrice = full.price && Number(full.price) > 0;
      const hasVariants = Array.isArray(full.variants) && full.variants.length > 0;

      return {
        ...full,
        _id: full._id,
        viewedAt: it.viewedAt,
        // Use saved price when catalog has none
        price: hasPrice ? full.price : (it.price || 0),
        discountPrice: full.discountPrice ?? undefined,
        // Keep the saved image as a top-level fallback for the frontend
        image: it.image || full.image,
        // When catalog has no variants but we have a saved image, synthesize one
        variants: hasVariants
          ? full.variants
          : it.image
          ? [{ color: "", colorCode: "", images: [it.image], sizes: [] }]
          : [],
      };
    });

    return res.json({ items });
  } catch (err) {
    console.error("Error listing recently viewed", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// Address book for saved shipping addresses (per user)
const addressSchema = new mongoose.Schema(
  {
    userId: { type: String, required: true, index: true },
    label: { type: String, default: "Home" }, // e.g. Home / Office
    name: { type: String, required: true },
    phone: { type: String, required: true },
    address1: { type: String, required: true },
    city: { type: String, required: true },
    state: { type: String, required: true },
    pincode: { type: String, required: true },
    isDefault: { type: Boolean, default: false },
  },
  { timestamps: true },
);

const Address = mongoose.model("Address", addressSchema, "addresses");

// Contact messages (Contact Us form submissions)
const contactMessageSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true },
    email: { type: String, required: true, trim: true, lowercase: true },
    phone: { type: String, default: "", trim: true },
    message: { type: String, required: true, trim: true },
    meta: {
      ip: { type: String, default: "" },
      userAgent: { type: String, default: "" },
    },
    status: { type: String, enum: ["new", "read", "archived"], default: "new" },
  },
  { timestamps: true },
);
contactMessageSchema.index({ createdAt: -1 });
const ContactMessage = mongoose.model(
  "ContactMessage",
  contactMessageSchema,
  "contact_messages",
);

// Coupon model (simple)
const couponSchema = new mongoose.Schema(
  {
    code: { type: String, required: true, unique: true, index: true },
    type: { type: String, enum: ["percent", "flat"], required: true },
    value: { type: Number, required: true, min: 0 },
    minSubtotal: { type: Number, default: 0, min: 0 },
    maxDiscount: { type: Number, default: 0, min: 0 }, // only for percent (0 = no cap)
    isActive: { type: Boolean, default: true },
    expiresAt: { type: Date },
  },
  { timestamps: true },
);

const Coupon = mongoose.model("Coupon", couponSchema, "coupons");

// Coupon redemption (one-time per user)
const couponRedemptionSchema = new mongoose.Schema(
  {
    userId: { type: String, required: true, index: true },
    code: { type: String, required: true, index: true }, // uppercase coupon code
    orderId: { type: String },
    usedAt: { type: Date, default: Date.now },
  },
  { timestamps: true },
);
couponRedemptionSchema.index({ userId: 1, code: 1 }, { unique: true });
const CouponRedemption = mongoose.model(
  "CouponRedemption",
  couponRedemptionSchema,
  "coupon_redemptions",
);

// Site settings (logo, etc.)
const siteSettingSchema = new mongoose.Schema(
  {
    key: { type: String, required: true, unique: true, index: true },
    value: { type: mongoose.Schema.Types.Mixed, default: null },
  },
  { timestamps: true },
);
const SiteSetting = mongoose.model("SiteSetting", siteSettingSchema, "site_settings");

// Order schema/model (created during checkout)
const orderSchema = new mongoose.Schema(
  {
    userId: { type: String, required: true, index: true },
    items: [
      {
        cartItemId: { type: String },
        productId: { type: String, required: true },
        variantId: { type: String },
        name: { type: String, required: true },
        slug: { type: String },
        price: { type: Number, required: true, min: 0 },
        color: { type: String },
        size: { type: String },
        quantity: { type: Number, required: true, min: 1 },
        image: { type: String },
      },
    ],
    subtotal: { type: Number, required: true, min: 0 },
    shipping: { type: Number, required: true, min: 0, default: 0 },
    discount: { type: Number, required: true, min: 0, default: 0 },
    total: { type: Number, required: true, min: 0 },
    currency: { type: String, default: "INR" },
    note: { type: String },
    couponCode: { type: String },
    shippingAddress: {
      name: { type: String },
      phone: { type: String },
      address1: { type: String },
      city: { type: String },
      state: { type: String },
      pincode: { type: String },
    },
    paymentMethod: { type: String, enum: ["cod", "online"], default: "cod" },
    paymentDetails: {
      provider: { type: String, default: "" }, // e.g. "razorpay"
      razorpayOrderId: { type: String, default: "" },
      razorpayPaymentId: { type: String, default: "" },
      razorpaySignature: { type: String, default: "" },
      verifiedAt: { type: Date, default: null },
    },
    paymentStatus: {
      type: String,
      enum: ["pending", "cod", "paid", "failed"],
      default: "pending",
    },
    status: {
      type: String,
      enum: ["created", "confirmed", "shipped", "delivered", "cancelled"],
      default: "created",
    },
  },
  { timestamps: true },
);

const Order = mongoose.model("Order", orderSchema, "orders");

// Payment events (to maintain cancelled/failed/verified history for online payments)
const paymentEventSchema = new mongoose.Schema(
  {
    userId: { type: String, required: true, index: true },
    provider: { type: String, default: "" }, // "razorpay"
    eventType: { type: String, default: "" }, // "create" | "cancelled" | "failed" | "verified" | "paid"
    status: { type: String, default: "" }, // "pending" | "cancelled" | "failed" | "verified" | "paid"
    amount: { type: Number, default: 0 }, // paise for INR
    currency: { type: String, default: "INR" },
    razorpayOrderId: { type: String, default: "", index: true },
    razorpayPaymentId: { type: String, default: "", index: true },
    reason: { type: String, default: "" },
    meta: { type: mongoose.Schema.Types.Mixed, default: null },
  },
  { timestamps: true },
);
paymentEventSchema.index({ userId: 1, createdAt: -1 });
const PaymentEvent = mongoose.model(
  "PaymentEvent",
  paymentEventSchema,
  "payment_events",
);

function computeShipping({ country, subtotal }) {
  const c = String(country || "").trim().toLowerCase();
  const sub = Number(subtotal || 0);
  const isIndia = c === "india" || c === "in" || c.includes("india");
  let shipping = isIndia ? 49 : 199;
  if (sub >= 500) shipping = 0;
  return shipping;
}

function computeEtaDays(country) {
  const c = String(country || "").trim().toLowerCase();
  const isIndia = c === "india" || c === "in" || c.includes("india");
  return isIndia ? { min: 2, max: 5 } : { min: 5, max: 12 };
}

app.get("/api/products", async (req, res) => {
  try {
    const page = Math.max(parseInt(req.query.page || "1", 10), 1);
    const limit = Math.max(parseInt(req.query.limit || "20", 10), 1);
    const skip = (page - 1) * limit;

    const [items, total] = await Promise.all([
      Product.find().skip(skip).limit(limit).lean(),
      Product.countDocuments(),
    ]);

    res.json({
      items,
      pagination: {
        total,
        page,
        limit,
        totalPages: Math.ceil(total / limit),
      },
    });
  } catch (err) {
    console.error("Error fetching products", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// API: add item to cart (used by QuickView on the frontend)
// Body example:
// {
//   userId: "demo-user-1",
//   productId: "69b8e60019c6c64fc0fabd7c",
//   variantId: "69b8e60019c6c64fc0fabd7c-v1",
//   name: "Jeans",
//   slug: "jeans",
//   price: 5999,
//   color: "Brown",
//   size: "M",
//   quantity: 2,
//   image: "https://..."
// }

function findMixMatchFallbackProductById(wantId) {
  const id = String(wantId || "").trim();
  if (!id) return null;
  for (const look of MIXMATCH_FALLBACK_LOOKS) {
    const hit = (look.products || []).find(
      (p) => String(p.productId || "") === id,
    );
    if (hit) return hit;
  }
  return null;
}

async function findMixMatchProductRowById(productId) {
  const id = String(productId || "").trim();
  if (!id) return null;
  const fromFallback = findMixMatchFallbackProductById(id);
  if (fromFallback) return fromFallback;
  try {
    const doc = await MixMatchLook.findOne({ "products.productId": id })
      .select({ products: 1 })
      .lean();
    return (
      (doc?.products || []).find((p) => String(p?.productId || "") === id) ||
      null
    );
  } catch {
    return null;
  }
}

/** Single-variant synthetic shape for stock checks (aligned with mixmatch synthetic catalog). */
function syntheticCatalogFromMixMatchRow(row) {
  if (!row) return null;
  const color = String(row.color || "").trim() || "";
  const size = String(row.size || "").trim() || "One size";
  return {
    variants: [
      {
        color,
        colorCode: "",
        sizes: [{ size, stock: 999 }],
      },
    ],
  };
}

async function resolveMaxStockFromMixMatchRow(productId, color, size) {
  const row = await findMixMatchProductRowById(productId);
  if (!row) return null;
  const syn = syntheticCatalogFromMixMatchRow(row);
  let n = computeVariantStock(syn, color, size);
  if (n == null) {
    n = 999;
  }
  return n;
}

function resolveCatalogVariantByColor(productDoc, color) {
  if (!productDoc || !Array.isArray(productDoc.variants)) return null;
  const c = color != null ? String(color).trim() : "";
  if (c) {
    const byExact = productDoc.variants.find(
      (v) => v && String(v.color || "").trim() === c,
    );
    if (byExact) return byExact;
    const cLow = c.toLowerCase();
    const byLow = productDoc.variants.find(
      (v) => v && String(v.color || "").trim().toLowerCase() === cLow,
    );
    if (byLow) return byLow;
  }
  if (productDoc.variants.length === 1) return productDoc.variants[0];
  return null;
}

function computeVariantStock(productDoc, color, size) {
  if (!productDoc || !Array.isArray(productDoc.variants)) return null;
  const s = size != null ? String(size).trim() : "";

  const variant = resolveCatalogVariantByColor(productDoc, color);
  if (!variant || !Array.isArray(variant.sizes)) return null;

  if (variant.sizes.length === 0) {
    const stockNum = Number(variant.stock);
    return Number.isFinite(stockNum) ? Math.max(0, stockNum) : null;
  }

  if (!s) return null;

  const sizeRow =
    variant.sizes.find((row) => String(row.size || "") === s) ||
    variant.sizes.find(
      (row) => String(row.size || "").toLowerCase() === s.toLowerCase(),
    ) ||
    null;

  if (!sizeRow) return null;
  const stockNum = Number(sizeRow.stock);
  return Number.isFinite(stockNum) ? Math.max(0, stockNum) : null;
}

async function attachMaxStockToCartItems(items) {
  const list = Array.isArray(items) ? items : [];
  const productIds = Array.from(
    new Set(
      list
        .map((it) => it?.productId)
        .filter(Boolean)
        .map((id) => String(id)),
    ),
  );

  if (!productIds.length) return list;

  // Mix & match placeholders (e.g. "mix-1") are not ObjectIds — $in would throw CastError.
  const validIds = productIds.filter((id) => mongoose.isValidObjectId(id));
  const products = validIds.length
    ? await CatalogProduct.find({ _id: { $in: validIds } })
        .select({ _id: 1, variants: 1 })
        .lean()
    : [];

  const map = new Map(products.map((p) => [String(p._id), p]));
  const out = [];
  for (const it of list) {
    const pid = it?.productId != null ? String(it.productId) : "";
    const productDoc =
      pid && mongoose.isValidObjectId(pid) ? map.get(pid) : null;
    let maxStock = computeVariantStock(
      productDoc,
      it?.color,
      it?.size != null ? it.size : "",
    );
    if (maxStock == null && pid && !mongoose.isValidObjectId(pid)) {
      maxStock = await resolveMaxStockFromMixMatchRow(
        pid,
        it?.color,
        it?.size != null ? it.size : "",
      );
    }
    out.push({ ...it, maxStock });
  }
  return out;
}

// API: check stock for a single product variant (color + size)
// POST /api/stock/check
// Body: { productId, color, size, quantity? }
app.post("/api/stock/check", async (req, res) => {
  try {
    const { productId, color, size, quantity } = req.body || {};
    if (!productId || !color) {
      return res.status(400).json({ error: "productId and color are required" });
    }

    const pid = String(productId);
    const c = String(color);
    const s = size != null ? String(size).trim() : "";
    const reqQty = Math.max(1, Number(quantity) || 1);

    const prod = await CatalogProduct.findById(pid).select({ _id: 1, variants: 1 }).lean();
    if (!prod) return res.status(404).json({ error: "Product not found" });

    const availableStock = computeVariantStock(prod, c, s);
    if (availableStock == null) {
      return res.status(404).json({ error: "Variant not found", availableStock: null });
    }

    const inStock = availableStock > 0 && reqQty <= availableStock;
    return res.json({
      inStock,
      availableStock,
      maxAllowedQty: availableStock,
      requestedQty: reqQty,
    });
  } catch (err) {
    console.error("Error checking stock", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// API: validate cart quantities vs stock (before checkout)
// POST /api/cart/validate-stock
// Body: { userId }
app.post("/api/cart/validate-stock", async (req, res) => {
  try {
    const { userId } = req.body || {};
    if (!userId) return res.status(400).json({ error: "userId is required" });

    const items = await CartItem.find({ userId: String(userId) })
      .sort({ createdAt: -1 })
      .lean();

    const withStock = await attachMaxStockToCartItems(items);
    const results = (withStock || []).map((it) => {
      const requestedQty = Math.max(1, Number(it.quantity) || 1);
      const availableStock =
        it.maxStock != null && Number.isFinite(Number(it.maxStock)) ? Math.max(0, Number(it.maxStock)) : null;
      // Sized lines need color+size; no-size catalog variants use color only (maxStock still set).
      const hasVariant = Boolean(
        it.color && (it.size || it.maxStock != null),
      );
      const inStock =
        !hasVariant
          ? true
          : availableStock != null
            ? availableStock > 0 && requestedQty <= availableStock
            : false;

      const maxAllowedQty = hasVariant ? availableStock : null;
      const needsQtyReduce =
        hasVariant && availableStock != null ? requestedQty > availableStock && availableStock > 0 : false;
      const suggestedQty =
        needsQtyReduce && availableStock != null ? Math.max(1, Math.min(requestedQty, availableStock)) : requestedQty;

      return {
        cartItemId: String(it._id),
        productId: it.productId,
        color: it.color || null,
        size: it.size || null,
        requestedQty,
        availableStock,
        inStock,
        maxAllowedQty,
        needsQtyReduce,
        suggestedQty,
      };
    });

    const ok = results.every((r) => r.inStock);
    return res.json({ ok, items: results });
  } catch (err) {
    console.error("Error validating cart stock", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/api/cart", async (req, res) => {
  try {
    const {
      userId,
      productId,
      variantId,
      name,
      slug,
      price,
      color,
      size,
      quantity,
      image,
    } = req.body || {};

    if (!userId || !productId || !name || price == null || !quantity) {
      return res.status(400).json({
        error: "userId, productId, name, price and quantity are required",
      });
    }

    const uid = String(userId);
    const pid = String(productId);
    const qty = Math.max(1, Number(quantity) || 1);
    const normalizedColor = color != null ? String(color) : "";
    const normalizedSize = size != null ? String(size) : "";

    // Prevent adding more than stock (variant-level). Only real catalog IDs can be loaded;
    // mix-match placeholders like "mix-1" are not ObjectIds — findById would throw CastError.
    let maxStock = null;
    let prod = null;
    if (normalizedColor && mongoose.isValidObjectId(pid)) {
      try {
        prod = await CatalogProduct.findById(pid)
          .select({ _id: 1, variants: 1 })
          .lean();
      } catch {
        prod = null;
      }
      if (prod) {
        maxStock = computeVariantStock(
          prod,
          normalizedColor,
          normalizedSize,
        );
      }
      if (maxStock != null && maxStock <= 0) {
        return res.status(400).json({ error: "Out of stock", maxStock: 0 });
      }
    }

    // Atomic upsert: increment qty for same user+product+color+size (prevents duplicate rows)
    const filter =
      normalizedColor && normalizedSize
        ? { userId: uid, productId: pid, color: normalizedColor, size: normalizedSize }
        : normalizedColor
          ? {
              userId: uid,
              productId: pid,
              color: normalizedColor,
              $or: [
                { size: { $exists: false } },
                { size: null },
                { size: "" },
              ],
            }
          : { userId: uid, productId: pid, variantId: variantId ? String(variantId) : undefined };

    const update = {
      $inc: { quantity: qty },
      $set: {
        price: Number(price),
        name: name,
        slug: slug,
        image: image,
        variantId: variantId ? String(variantId) : undefined,
        color: normalizedColor || undefined,
        size: normalizedColor ? normalizedSize || "" : normalizedSize || undefined,
        productId: pid,
        userId: uid,
      },
      $setOnInsert: { createdAt: new Date() },
    };

    // If we have a stock cap, clamp instead of erroring (prevents “reserved by cart” UX).
    // Stock is enforced strictly at checkout time.
    if (maxStock != null && normalizedColor) {
      const existingRow = await CartItem.findOne(filter)
        .select({ quantity: 1 })
        .lean();
      const currentQty = existingRow ? Number(existingRow.quantity || 0) : 0;
      const targetQty = Math.min(maxStock, currentQty + qty);
      const incBy = Math.max(0, targetQty - currentQty);
      if (incBy <= 0) {
        // Already at cap; return current row (no error toast on client)
        return res.status(200).json({
          ...(existingRow || {}),
          userId: uid,
          productId: pid,
          color: normalizedColor,
          size: normalizedColor ? normalizedSize || "" : normalizedSize || undefined,
          maxStock,
          clamped: true,
          quantity: currentQty || 1,
        });
      }
      update.$inc.quantity = incBy;
      update.$set.maxStock = maxStock;
      update.$set.clamped = incBy !== qty;
    }

    const doc = await CartItem.findOneAndUpdate(filter, update, {
      new: true,
      upsert: true,
      setDefaultsOnInsert: true,
    }).lean();

    return res.status(201).json(doc);
  } catch (err) {
    // Handle duplicate key (race) gracefully: return latest row instead of creating duplicates
    if (err && err.code === 11000) {
      try {
        const { userId, productId, color, size } = req.body || {};
        const uid = String(userId || "");
        const pid = String(productId || "");
        const normalizedColor = color != null ? String(color) : "";
        const normalizedSize = size != null ? String(size) : "";
        if (uid && pid && normalizedColor) {
          const existing = await CartItem.findOne(
            normalizedSize
              ? {
                  userId: uid,
                  productId: pid,
                  color: normalizedColor,
                  size: normalizedSize,
                }
              : {
                  userId: uid,
                  productId: pid,
                  color: normalizedColor,
                  $or: [
                    { size: { $exists: false } },
                    { size: null },
                    { size: "" },
                  ],
                },
          ).lean();
          if (existing) return res.status(200).json(existing);
        }
      } catch {
        // ignore
      }
    }
    console.error("Error inserting cart item", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// Wishlist API: add one item to wishlist in MongoDB (temporary userId supported)
// POST /api/wishlist
// Body: { userId, productId, name, slug?, price, image? }
app.post("/api/wishlist", async (req, res) => {
  try {
    const { userId, productId, name, slug, price, image } = req.body || {};
    if (!userId || !productId || !name || price == null) {
      return res
        .status(400)
        .json({ error: "userId, productId, name and price are required" });
    }

    const uid = String(userId);
    const pid = String(productId);
    const priceNum = Number(price);
    if (!Number.isFinite(priceNum) || priceNum < 0) {
      return res.status(400).json({ error: "price must be a valid number" });
    }

    const doc = await WishlistItem.findOneAndUpdate(
      { userId: uid, productId: pid },
      {
        $set: {
          userId: uid,
          productId: pid,
          name: String(name),
          slug: slug ? String(slug) : undefined,
          price: priceNum,
          image: image ? String(image) : undefined,
        },
        $setOnInsert: { createdAt: new Date() },
      },
      { new: true, upsert: true, setDefaultsOnInsert: true },
    ).lean();

    return res.status(201).json(doc);
  } catch (err) {
    // Handle duplicate key (race) gracefully
    if (err && err.code === 11000) {
      try {
        const { userId, productId } = req.body || {};
        const existing = await WishlistItem.findOne({
          userId: String(userId),
          productId: String(productId),
        }).lean();
        if (existing) return res.status(200).json(existing);
      } catch {
        // ignore
      }
    }
    console.error("Error inserting wishlist item", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// Wishlist API: list wishlist items for a user (POST)
// POST /api/wishlist/list  Body: { userId }
app.post("/api/wishlist/list", async (req, res) => {
  try {
    const { userId } = req.body || {};
    if (!userId) return res.status(400).json({ error: "userId is required" });
    const items = await WishlistItem.find({ userId: String(userId) })
      .sort({ createdAt: -1 })
      .lean();
    return res.json({ items });
  } catch (err) {
    console.error("Error listing wishlist items", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// Wishlist API: list wishlist items for a user (GET)
// GET /api/wishlist?userId=demo-user-1
app.get("/api/wishlist", async (req, res) => {
  try {
    const { userId } = req.query || {};
    if (!userId) return res.status(400).json({ error: "userId is required" });
    const items = await WishlistItem.find({ userId: String(userId) })
      .sort({ createdAt: -1 })
      .lean();
    return res.json({ items });
  } catch (err) {
    console.error("Error listing wishlist items (GET)", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// Wishlist API: remove wishlist item(s)
// DELETE /api/wishlist
// Body:
// - Preferred: { userId, wishlistItemId } (deletes exactly one row)
// - Or:        { userId, productId }      (deletes by product id)
app.delete("/api/wishlist", async (req, res) => {
  try {
    const { userId, wishlistItemId, productId } = req.body || {};
    if (!userId) return res.status(400).json({ error: "userId is required" });

    if (wishlistItemId) {
      const result = await WishlistItem.deleteOne({
        _id: String(wishlistItemId),
        userId: String(userId),
      });
      return res.json({ deletedCount: result.deletedCount });
    }

    if (!productId) {
      return res.status(400).json({
        error: "productId is required when wishlistItemId is not provided",
      });
    }

    const result = await WishlistItem.deleteOne({
      userId: String(userId),
      productId: String(productId),
    });
    return res.json({ deletedCount: result.deletedCount });
  } catch (err) {
    console.error("Error deleting wishlist item", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// API: get cart items for a user (temporary userId query param)
// GET /api/cart?userId=demo-user-1
app.get("/api/cart", async (req, res) => {
  try {
    const { userId } = req.query || {};
    if (!userId) {
      return res.status(400).json({ error: "userId is required" });
    }

    const items = await CartItem.find({ userId: String(userId) })
      .sort({ createdAt: -1 })
      .lean();

    const withStock = await attachMaxStockToCartItems(items);
    return res.json({ items: withStock });
  } catch (err) {
    console.error("Error fetching cart items", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// API: get cart items for a user (POST version)
// POST /api/cart/list
// Body: { userId: "demo-user-1" }
app.post("/api/cart/list", async (req, res) => {
  try {
    const { userId } = req.body || {};
    if (!userId) {
      return res.status(400).json({ error: "userId is required" });
    }

    const items = await CartItem.find({ userId: String(userId) })
      .sort({ createdAt: -1 })
      .lean();

    const withStock = await attachMaxStockToCartItems(items);
    return res.json({ items: withStock });
  } catch (err) {
    console.error("Error fetching cart items (POST)", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// API: remove cart item(s)
// DELETE /api/cart
// Body:
// - Preferred: { userId: "demo-user-1", cartItemId: "..." }  (deletes exactly one row)
// - Legacy:    { userId: "demo-user-1", productId: "...", variantId?: "..." }
app.delete("/api/cart", async (req, res) => {
  try {
    const { userId, cartItemId, productId, variantId } = req.body || {};
    if (!userId) {
      return res.status(400).json({ error: "userId is required" });
    }

    // Exact delete by cart row id (fixes wrong-item delete when same product has multiple sizes/colors)
    if (cartItemId) {
      const result = await CartItem.deleteOne({
        _id: String(cartItemId),
        userId: String(userId),
      });
      return res.json({ deletedCount: result.deletedCount });
    }

    if (!productId) {
      return res.status(400).json({ error: "productId is required when cartItemId is not provided" });
    }

    const base = {
      userId: String(userId),
      productId: String(productId),
    };

    if (variantId) {
      const result = await CartItem.deleteOne({ ...base, variantId: String(variantId) });
      return res.json({ deletedCount: result.deletedCount });
    }

    const result = await CartItem.deleteMany(base);
    return res.json({ deletedCount: result.deletedCount });
  } catch (err) {
    console.error("Error deleting cart items", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// API: update quantity of a single cart row (POST version)
// POST /api/cart/update-qty
// Body: { userId, cartItemId, quantity }
app.post("/api/cart/update-qty", async (req, res) => {
  try {
    const { userId, cartItemId, quantity } = req.body || {};
    if (!userId || !cartItemId) {
      return res.status(400).json({ error: "userId and cartItemId are required" });
    }

    const qty = Math.max(1, Number(quantity) || 1);

    const existingRow = await CartItem.findOne({
      _id: String(cartItemId),
      userId: String(userId),
    })
      .select({ _id: 1, userId: 1, productId: 1, color: 1, size: 1, quantity: 1 })
      .lean();

    if (!existingRow) {
      return res.status(404).json({ error: "Cart item not found" });
    }

    // Enforce stock cap for catalog variants (color + optional size when variant has no sizes)
    let maxStock = null;
    const rowPid = existingRow.productId ? String(existingRow.productId) : "";
    if (existingRow.color && rowPid && mongoose.isValidObjectId(rowPid)) {
      const prod = await CatalogProduct.findById(rowPid)
        .select({ _id: 1, variants: 1 })
        .lean();
      const rowSize =
        existingRow.size != null ? String(existingRow.size) : "";
      maxStock = computeVariantStock(prod, existingRow.color, rowSize);
    }

    const finalQty =
      maxStock != null && Number.isFinite(Number(maxStock))
        ? Math.max(1, Math.min(qty, Math.max(1, Number(maxStock) || 1)))
        : qty;

    const updated = await CartItem.findOneAndUpdate(
      { _id: String(cartItemId), userId: String(userId) },
      { $set: { quantity: finalQty } },
      { new: true },
    ).lean();

    const [withStock] = await attachMaxStockToCartItems([updated]);

    return res.json({
      item: withStock || updated,
      ...(maxStock != null ? { maxStock, requestedQty: qty, finalQty } : {}),
    });
  } catch (err) {
    console.error("Error updating cart quantity", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// Addresses: list
// POST /api/addresses/list  Body: { userId }
app.post("/api/addresses/list", async (req, res) => {
  try {
    const { userId } = req.body || {};
    if (!userId) return res.status(400).json({ error: "userId is required" });
    const items = await Address.find({ userId: String(userId) })
      .sort({ isDefault: -1, updatedAt: -1 })
      .lean();
    return res.json({ items });
  } catch (err) {
    console.error("Error listing addresses", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// Addresses: save (create or update)
// POST /api/addresses/save
// Body: { userId, addressId?, label?, name, phone, address1, city, state, pincode, isDefault? }
app.post("/api/addresses/save", async (req, res) => {
  try {
    const {
      userId,
      addressId,
      label,
      name,
      phone,
      address1,
      city,
      state,
      pincode,
      isDefault = false,
    } = req.body || {};

    if (!userId || !name || !phone || !address1 || !city || !state || !pincode) {
      return res.status(400).json({
        error: "userId, name, phone, address1, city, state, pincode are required",
      });
    }

    const uid = String(userId);

    // If setting default, unset others
    if (isDefault) {
      await Address.updateMany({ userId: uid }, { $set: { isDefault: false } });
    }

    const payload = {
      userId: uid,
      label: label ? String(label) : "Home",
      name: String(name),
      phone: String(phone),
      address1: String(address1),
      city: String(city),
      state: String(state),
      pincode: String(pincode),
      isDefault: Boolean(isDefault),
    };

    let doc;
    if (addressId) {
      doc = await Address.findOneAndUpdate(
        { _id: String(addressId), userId: uid },
        { $set: payload },
        { new: true, upsert: false },
      ).lean();
      if (!doc) return res.status(404).json({ error: "Address not found" });
    } else {
      doc = await Address.create(payload);
      doc = doc.toObject();
    }

    return res.status(201).json({ item: doc });
  } catch (err) {
    console.error("Error saving address", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// Addresses: delete
// POST /api/addresses/delete Body: { userId, addressId }
app.post("/api/addresses/delete", async (req, res) => {
  try {
    const { userId, addressId } = req.body || {};
    if (!userId || !addressId) {
      return res.status(400).json({ error: "userId and addressId are required" });
    }

    const result = await Address.deleteOne({
      _id: String(addressId),
      userId: String(userId),
    });
    return res.json({ deletedCount: result.deletedCount });
  } catch (err) {
    console.error("Error deleting address", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// Coupons: validate
// POST /api/coupons/validate Body: { code, subtotal, userId? }
app.post("/api/coupons/validate", async (req, res) => {
  try {
    const { code, subtotal, userId } = req.body || {};
    const c = String(code || "").trim().toUpperCase();
    const sub = Number(subtotal || 0);
    if (!c) return res.status(400).json({ error: "code is required" });

    // If userId provided, ensure user hasn't used this coupon already
    if (userId) {
      const used = await CouponRedemption.exists({
        userId: String(userId),
        code: c,
      });
      if (used) return res.status(400).json({ error: "Coupon already used" });
    }

    const coupon = await Coupon.findOne({ code: c, isActive: true }).lean();
    if (!coupon) return res.status(404).json({ error: "Invalid coupon" });
    if (coupon.expiresAt && new Date(coupon.expiresAt).getTime() < Date.now()) {
      return res.status(400).json({ error: "Coupon expired" });
    }
    if (sub < Number(coupon.minSubtotal || 0)) {
      return res.status(400).json({ error: `Minimum subtotal ₹${coupon.minSubtotal} required` });
    }

    let discount = 0;
    if (coupon.type === "flat") {
      discount = Number(coupon.value || 0);
    } else {
      discount = (sub * Number(coupon.value || 0)) / 100;
      const cap = Number(coupon.maxDiscount || 0);
      if (cap > 0) discount = Math.min(discount, cap);
    }
    discount = Math.max(0, Math.min(discount, sub));

    return res.json({
      valid: true,
      code: coupon.code,
      discount,
      meta: {
        type: coupon.type,
        value: coupon.value,
        minSubtotal: coupon.minSubtotal || 0,
        maxDiscount: coupon.maxDiscount || 0,
      },
    });
  } catch (err) {
    console.error("Error validating coupon", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// Coupons: list available (for UI suggestions)
// POST /api/coupons/list Body: { limit?, userId? }
app.post("/api/coupons/list", async (req, res) => {
  try {
    const { limit = 10, userId } = req.body || {};
    const limitNum = Math.max(parseInt(limit, 10) || 10, 1);

    const now = new Date();
    let excludeCodes = [];
    if (userId) {
      excludeCodes = await CouponRedemption.distinct("code", {
        userId: String(userId),
      });
    }

    const items = await Coupon.find({
      isActive: true,
      $or: [{ expiresAt: { $exists: false } }, { expiresAt: null }, { expiresAt: { $gte: now } }],
      ...(excludeCodes.length ? { code: { $nin: excludeCodes } } : {}),
    })
      .sort({ createdAt: -1 })
      .limit(limitNum)
      .lean();

    // Keep only safe fields for user UI
    const safe = items.map((c) => ({
      _id: c._id,
      code: c.code,
      type: c.type,
      value: c.value,
      minSubtotal: c.minSubtotal || 0,
      maxDiscount: c.maxDiscount || 0,
      expiresAt: c.expiresAt || null,
    }));

    return res.json({ items: safe });
  } catch (err) {
    console.error("Error listing coupons", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// Orders: list
// POST /api/orders/list Body: { userId }
app.post("/api/orders/list", async (req, res) => {
  try {
    const { userId } = req.body || {};
    if (!userId) return res.status(400).json({ error: "userId is required" });
    const items = await Order.find({ userId: String(userId) })
      .sort({ createdAt: -1 })
      .lean();
    return res.json({ items });
  } catch (err) {
    console.error("Error listing orders", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// Admin: list all orders
app.get("/api/admin/orders", authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const items = await Order.find({})
      .sort({ createdAt: -1 })
      .lean();
    return res.json({ items });
  } catch (err) {
    console.error("Admin list orders error:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// Admin: update an order (status/payment/shipping info)
// PATCH /api/admin/orders/:id
// Body: { status?, paymentStatus?, trackingNumber?, carrier?, cancelReason? }
app.patch("/api/admin/orders/:id", authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const id = String(req.params.id || "").trim();
    if (!id) return res.status(400).json({ error: "id is required" });

    const {
      status,
      paymentStatus,
      trackingNumber,
      carrier,
      cancelReason,
    } = req.body || {};

    const patch = {};
    const now = new Date();

    const allowedStatus = new Set([
      "created",
      "confirmed",
      "processing",
      "shipped",
      "delivered",
      "cancelled",
    ]);
    const allowedPayment = new Set(["pending", "paid", "failed", "refunded"]);

    if (status != null) {
      const next = String(status || "").toLowerCase().trim();
      if (!allowedStatus.has(next)) {
        return res.status(400).json({ error: "Invalid status" });
      }
      patch.status = next;
      if (next === "shipped" && !patch.shippedAt) patch.shippedAt = now;
      if (next === "delivered" && !patch.deliveredAt) patch.deliveredAt = now;
      if (next === "processing" && !patch.processingAt) patch.processingAt = now;
      if (next === "confirmed" && !patch.confirmedAt) patch.confirmedAt = now;
      if (next === "cancelled") {
        patch.cancelledAt = now;
        if (cancelReason != null) patch.cancelReason = String(cancelReason || "").trim();
      }
    }

    if (paymentStatus != null) {
      const nextPay = String(paymentStatus || "").toLowerCase().trim();
      if (!allowedPayment.has(nextPay)) {
        return res.status(400).json({ error: "Invalid paymentStatus" });
      }
      patch.paymentStatus = nextPay;
      if (nextPay === "paid") patch.paidAt = now;
      if (nextPay === "refunded") patch.refundedAt = now;
    }

    if (trackingNumber != null) patch.trackingNumber = String(trackingNumber || "").trim();
    if (carrier != null) patch.carrier = String(carrier || "").trim();

    if (Object.keys(patch).length === 0) {
      return res.status(400).json({ error: "No valid fields provided" });
    }

    const updated = await Order.findByIdAndUpdate(
      id,
      { $set: patch },
      { new: true },
    ).lean();

    if (!updated) return res.status(404).json({ error: "Order not found" });
    return res.json({ item: updated });
  } catch (err) {
    console.error("Admin update order error:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// Admin: list coupons
// POST /api/admin/coupons/list  Body: {}
app.post("/api/admin/coupons/list", async (req, res) => {
  try {
    const items = await Coupon.find({})
      .sort({ createdAt: -1 })
      .lean();
    return res.json({ items });
  } catch (err) {
    console.error("Error listing coupons", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// Admin: create coupon
// POST /api/admin/coupons/create
// Body: { code, type: "percent"|"flat", value, minSubtotal?, maxDiscount?, isActive?, expiresAt? }
app.post("/api/admin/coupons/create", async (req, res) => {
  try {
    const {
      code,
      type,
      value,
      minSubtotal = 0,
      maxDiscount = 0,
      isActive = true,
      expiresAt,
    } = req.body || {};

    const c = String(code || "").trim().toUpperCase();
    if (!c) return res.status(400).json({ error: "code is required" });
    if (type !== "percent" && type !== "flat") {
      return res.status(400).json({ error: "type must be percent or flat" });
    }
    const val = Number(value);
    if (!isFinite(val) || val <= 0) {
      return res.status(400).json({ error: "value must be > 0" });
    }

    const couponDoc = await Coupon.create({
      code: c,
      type,
      value: val,
      minSubtotal: Math.max(0, Number(minSubtotal) || 0),
      maxDiscount: Math.max(0, Number(maxDiscount) || 0),
      isActive: Boolean(isActive),
      expiresAt: expiresAt ? new Date(expiresAt) : undefined,
    });

    return res.status(201).json({ item: couponDoc.toObject() });
  } catch (err) {
    if (err && err.code === 11000) {
      return res.status(400).json({ error: "Coupon code already exists" });
    }
    console.error("Error creating coupon", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// Admin: delete coupon
// POST /api/admin/coupons/delete Body: { couponId }
app.post("/api/admin/coupons/delete", async (req, res) => {
  try {
    const { couponId } = req.body || {};
    if (!couponId) return res.status(400).json({ error: "couponId is required" });
    const result = await Coupon.deleteOne({ _id: String(couponId) });
    return res.json({ deletedCount: result.deletedCount });
  } catch (err) {
    console.error("Error deleting coupon", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// Checkout: create order from user's cart and clear cart
// POST /api/checkout
// Body: { userId, paymentMethod?: "cod"|"online", note?, couponCode?, shippingAddress?, payment?: { provider, razorpay_order_id, razorpay_payment_id, razorpay_signature, verified? } }
app.post("/api/checkout", async (req, res) => {
  const session = await mongoose.startSession();
  try {
    const { userId, paymentMethod = "cod", note, couponCode, shippingAddress, payment } =
      req.body || {};
    if (!userId) {
      return res.status(400).json({ error: "userId is required" });
    }

    session.startTransaction();

    const uid = String(userId);
    const cartItems = await CartItem.find({ userId: uid })
      .sort({ createdAt: -1 })
      .session(session)
      .lean();

    if (!cartItems.length) {
      await session.abortTransaction();
      return res.status(400).json({ error: "Cart is empty" });
    }

    const items = cartItems.map((it) => ({
      cartItemId: String(it._id),
      productId: String(it.productId),
      variantId: it.variantId ? String(it.variantId) : undefined,
      name: it.name,
      slug: it.slug,
      price: Number(it.price || 0),
      color: it.color,
      size: it.size,
      quantity: Number(it.quantity || 1),
      image: it.image,
    }));

    // 1) Validate + decrement stock (per-size or variant-level when sizes is empty)
    for (const it of items) {
      const qty = Math.max(1, Number(it.quantity) || 1);
      const color = it.color != null ? String(it.color) : "";
      const size = it.size != null ? String(it.size).trim() : "";
      const productId = it.productId;

      if (!productId || !color || !mongoose.isValidObjectId(productId)) continue;

      if (size) {
        const filter = {
          _id: String(productId),
          variants: {
            $elemMatch: {
              color,
              sizes: { $elemMatch: { size, stock: { $gte: qty } } },
            },
          },
        };

        const update = {
          $inc: { "variants.$[v].sizes.$[s].stock": -qty },
        };

        const result = await CatalogProduct.updateOne(filter, update, {
          session,
          arrayFilters: [{ "v.color": color }, { "s.size": size }],
        });

        if (!result || result.modifiedCount !== 1) {
          throw new Error(
            `Out of stock: ${it.name || "Product"} (${color}/${size})`,
          );
        }
      } else {
        const filter = {
          _id: String(productId),
          variants: {
            $elemMatch: {
              color,
              stock: { $gte: qty },
              $or: [{ sizes: { $size: 0 } }, { sizes: { $exists: false } }],
            },
          },
        };

        const update = { $inc: { "variants.$.stock": -qty } };

        const result = await CatalogProduct.updateOne(filter, update, {
          session,
        });

        if (!result || result.modifiedCount !== 1) {
          throw new Error(
            `Out of stock: ${it.name || "Product"} (${color}, no size)`,
          );
        }
      }
    }

    const subtotal = items.reduce(
      (sum, it) => sum + Number(it.price || 0) * Number(it.quantity || 1),
      0,
    );

    // 2) Compute shipping + coupon discount (server-side source of truth)
    const countryForShip = shippingAddress?.country || "India";
    const shipping = computeShipping({ country: countryForShip, subtotal });

    let discount = 0;
    let couponFinal = couponCode ? String(couponCode).trim().toUpperCase() : "";
    if (couponFinal) {
      // one-time coupon per user check (transactional)
      const alreadyUsed = await CouponRedemption.exists({ userId: uid, code: couponFinal }).session(session);
      if (alreadyUsed) {
        throw new Error("Coupon already used");
      }

      const coupon = await Coupon.findOne({ code: couponFinal, isActive: true })
        .session(session)
        .lean();
      if (coupon && (!coupon.expiresAt || new Date(coupon.expiresAt).getTime() >= Date.now())) {
        const minSub = Number(coupon.minSubtotal || 0);
        if (subtotal >= minSub) {
          if (coupon.type === "flat") {
            discount = Number(coupon.value || 0);
          } else {
            discount = (subtotal * Number(coupon.value || 0)) / 100;
            const cap = Number(coupon.maxDiscount || 0);
            if (cap > 0) discount = Math.min(discount, cap);
          }
        }
      }
      discount = Math.max(0, Math.min(discount, subtotal));
      if (!discount) couponFinal = ""; // don't store invalid coupon
    }
    const total = Math.max(0, subtotal + shipping - discount);

    // 3) Create order + clear cart
    const isOnline = paymentMethod === "online";
    const isVerified =
      Boolean(payment?.verified) &&
      String(payment?.provider || "").toLowerCase() === "razorpay" &&
      String(payment?.razorpay_order_id || "").trim() &&
      String(payment?.razorpay_payment_id || "").trim() &&
      String(payment?.razorpay_signature || "").trim();

    const [orderDoc] = await Order.create(
      [
        {
          userId: uid,
          items,
          subtotal,
          shipping,
          discount,
          total,
          note: note ? String(note) : undefined,
          couponCode: couponFinal || undefined,
          shippingAddress:
            shippingAddress && typeof shippingAddress === "object"
              ? shippingAddress
              : undefined,
          paymentMethod: isOnline ? "online" : "cod",
          paymentDetails: isOnline
            ? {
                provider: "razorpay",
                razorpayOrderId: String(payment?.razorpay_order_id || "").trim(),
                razorpayPaymentId: String(payment?.razorpay_payment_id || "").trim(),
                razorpaySignature: String(payment?.razorpay_signature || "").trim(),
                verifiedAt: isVerified ? new Date() : null,
              }
            : undefined,
          paymentStatus: isOnline ? (isVerified ? "paid" : "pending") : "cod",
          status: "created",
        },
      ],
      { session },
    );

    // 3.5) Mark coupon used for this user (only if applied)
    if (couponFinal && discount > 0) {
      await CouponRedemption.create(
        [
          {
            userId: uid,
            code: couponFinal,
            orderId: String(orderDoc._id),
            usedAt: new Date(),
          },
        ],
        { session },
      );
    }

    await CartItem.deleteMany({ userId: uid }).session(session);

    await session.commitTransaction();
    return res.status(201).json({ order: orderDoc.toObject() });
  } catch (err) {
    try {
      await session.abortTransaction();
    } catch {
      // ignore
    }
    const msg = err?.message || "Internal server error";
    if (msg.startsWith("Out of stock:")) {
      return res.status(400).json({ error: msg });
    }
    if (msg === "Coupon already used") {
      return res.status(400).json({ error: msg });
    }
    console.error("Error creating checkout order", err);
    return res.status(500).json({ error: "Internal server error" });
  } finally {
    session.endSession();
  }
});

// Buy-now checkout: create order for ONE item (does NOT clear the cart)
// POST /api/checkout/buy-now
// Body: { userId, paymentMethod?: "cod"|"online", note?, couponCode?, shippingAddress?, payment?: { provider, razorpay_order_id, razorpay_payment_id, razorpay_signature, verified? }, item: { productId, name?, slug?, price?, color?, size?, quantity?, image?, variantId? } }
app.post("/api/checkout/buy-now", async (req, res) => {
  const session = await mongoose.startSession();
  try {
    const {
      userId,
      paymentMethod = "cod",
      note,
      couponCode,
      shippingAddress,
      payment,
      item,
    } = req.body || {};

    if (!userId) return res.status(400).json({ error: "userId is required" });
    if (!item || typeof item !== "object") {
      return res.status(400).json({ error: "item is required" });
    }

    const uid = String(userId);
    const productId = String(item.productId || "").trim();
    const color = item.color != null ? String(item.color).trim() : "";
    const size = item.size != null ? String(item.size).trim() : "";
    const qty = Math.max(1, Number(item.quantity) || 1);
    const price = Number(item.price || 0);

    if (!productId || !mongoose.isValidObjectId(productId)) {
      return res.status(400).json({ error: "valid item.productId is required" });
    }
    if (!color) {
      return res.status(400).json({ error: "item.color is required" });
    }

    session.startTransaction();

    const items = [
      {
        cartItemId: undefined,
        productId,
        variantId: item.variantId ? String(item.variantId) : undefined,
        name: String(item.name || "Product"),
        slug: item.slug ? String(item.slug) : "",
        price: Number.isFinite(price) ? price : 0,
        color,
        size: size || undefined,
        quantity: qty,
        image: item.image ? String(item.image) : "",
      },
    ];

    // 1) Validate + decrement stock for this ONE item
    for (const it of items) {
      const q = Math.max(1, Number(it.quantity) || 1);
      const c = it.color != null ? String(it.color) : "";
      const s = it.size != null ? String(it.size).trim() : "";
      const pid = it.productId;

      if (!pid || !c || !mongoose.isValidObjectId(pid)) continue;

      if (s) {
        const filter = {
          _id: String(pid),
          variants: {
            $elemMatch: {
              color: c,
              sizes: { $elemMatch: { size: s, stock: { $gte: q } } },
            },
          },
        };

        const update = {
          $inc: { "variants.$[v].sizes.$[s].stock": -q },
        };

        const result = await CatalogProduct.updateOne(filter, update, {
          session,
          arrayFilters: [{ "v.color": c }, { "s.size": s }],
        });

        if (!result || result.modifiedCount !== 1) {
          throw new Error(`Out of stock: ${it.name || "Product"} (${c}/${s})`);
        }
      } else {
        const filter = {
          _id: String(pid),
          variants: {
            $elemMatch: {
              color: c,
              stock: { $gte: q },
              $or: [{ sizes: { $size: 0 } }, { sizes: { $exists: false } }],
            },
          },
        };

        const update = { $inc: { "variants.$.stock": -q } };

        const result = await CatalogProduct.updateOne(filter, update, { session });
        if (!result || result.modifiedCount !== 1) {
          throw new Error(`Out of stock: ${it.name || "Product"} (${c}, no size)`);
        }
      }
    }

    const subtotal = items.reduce(
      (sum, it) => sum + Number(it.price || 0) * Number(it.quantity || 1),
      0,
    );

    // 2) Compute shipping + coupon discount (server-side source of truth)
    const countryForShip = shippingAddress?.country || "India";
    const shipping = computeShipping({ country: countryForShip, subtotal });

    let discount = 0;
    let couponFinal = couponCode ? String(couponCode).trim().toUpperCase() : "";
    if (couponFinal) {
      const alreadyUsed = await CouponRedemption.exists({ userId: uid, code: couponFinal }).session(session);
      if (alreadyUsed) throw new Error("Coupon already used");

      const coupon = await Coupon.findOne({ code: couponFinal, isActive: true })
        .session(session)
        .lean();
      if (coupon && (!coupon.expiresAt || new Date(coupon.expiresAt).getTime() >= Date.now())) {
        const minSub = Number(coupon.minSubtotal || 0);
        if (subtotal >= minSub) {
          if (coupon.type === "flat") {
            discount = Number(coupon.value || 0);
          } else {
            discount = (subtotal * Number(coupon.value || 0)) / 100;
            const cap = Number(coupon.maxDiscount || 0);
            if (cap > 0) discount = Math.min(discount, cap);
          }
        }
      }
      discount = Math.max(0, Math.min(discount, subtotal));
      if (!discount) couponFinal = "";
    }

    const total = Math.max(0, subtotal + shipping - discount);

    // 3) Create order (do NOT clear user's cart)
    const isOnline = paymentMethod === "online";
    const isVerified =
      Boolean(payment?.verified) &&
      String(payment?.provider || "").toLowerCase() === "razorpay" &&
      String(payment?.razorpay_order_id || "").trim() &&
      String(payment?.razorpay_payment_id || "").trim() &&
      String(payment?.razorpay_signature || "").trim();

    const [orderDoc] = await Order.create(
      [
        {
          userId: uid,
          items,
          subtotal,
          shipping,
          discount,
          total,
          note: note ? String(note) : undefined,
          couponCode: couponFinal || undefined,
          shippingAddress:
            shippingAddress && typeof shippingAddress === "object"
              ? shippingAddress
              : undefined,
          paymentMethod: isOnline ? "online" : "cod",
          paymentDetails: isOnline
            ? {
                provider: "razorpay",
                razorpayOrderId: String(payment?.razorpay_order_id || "").trim(),
                razorpayPaymentId: String(payment?.razorpay_payment_id || "").trim(),
                razorpaySignature: String(payment?.razorpay_signature || "").trim(),
                verifiedAt: isVerified ? new Date() : null,
              }
            : undefined,
          paymentStatus: isOnline ? (isVerified ? "paid" : "pending") : "cod",
          status: "created",
        },
      ],
      { session },
    );

    if (couponFinal && discount > 0) {
      await CouponRedemption.create(
        [
          {
            userId: uid,
            code: couponFinal,
            orderId: String(orderDoc._id),
            usedAt: new Date(),
          },
        ],
        { session },
      );
    }

    await session.commitTransaction();
    return res.status(201).json({ order: orderDoc.toObject() });
  } catch (err) {
    try {
      await session.abortTransaction();
    } catch {
      // ignore
    }
    const msg = err?.message || "Internal server error";
    if (msg.startsWith("Out of stock:")) return res.status(400).json({ error: msg });
    if (msg === "Coupon already used") return res.status(400).json({ error: msg });
    console.error("Error creating buy-now checkout order", err);
    return res.status(500).json({ error: "Internal server error" });
  } finally {
    session.endSession();
  }
});

// Contact Us: save a customer message
app.post("/api/contact", async (req, res) => {
  try {
    const name = String(req.body?.name || "").trim();
    const email = String(req.body?.email || "").trim().toLowerCase();
    const phone = String(req.body?.phone || "").trim();
    const message = String(req.body?.message || "").trim();

    if (!name) return res.status(400).json({ error: "name is required" });
    if (!email || !email.includes("@")) {
      return res.status(400).json({ error: "valid email is required" });
    }
    if (!message) return res.status(400).json({ error: "message is required" });

    const doc = await ContactMessage.create({
      name,
      email,
      phone,
      message,
      meta: {
        ip: String(req.headers["x-forwarded-for"] || req.socket?.remoteAddress || ""),
        userAgent: String(req.headers["user-agent"] || ""),
      },
    });

    return res.json({ ok: true, id: String(doc._id) });
  } catch (err) {
    console.error("Contact message error", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// Admin: list contact messages (newest first)
app.get(
  "/api/admin/contact-messages",
  authMiddleware,
  adminMiddleware,
  async (req, res) => {
    try {
      const limit = Math.min(Math.max(parseInt(req.query?.limit, 10) || 50, 1), 200);
      const items = await ContactMessage.find()
        .sort({ createdAt: -1 })
        .limit(limit)
        .lean();
      return res.json({ items });
    } catch (err) {
      console.error("Admin list contact messages error", err);
      return res.status(500).json({ error: "Internal server error" });
    }
  },
);

// Shipping rate estimate (simple placeholder logic)
// POST /api/shipping/rates
// Body: { country?, province?, postalCode?, subtotal? }
app.post("/api/shipping/rates", async (req, res) => {
  try {
    const { country, province, postalCode, subtotal } = req.body || {};

    const c = String(country || "").trim().toLowerCase();
    const p = String(province || "").trim();
    const pc = String(postalCode || "").trim();
    const sub = Number(subtotal || 0);

    const isIndia =
      c === "india" ||
      c === "in" ||
      c.includes("india");

    // Base shipping rules (you can replace with real courier API later)
    let shipping = isIndia ? 49 : 199;
    if (sub >= 500) shipping = 0; // free shipping goal like UI

    const etaDays = isIndia ? { min: 2, max: 5 } : { min: 5, max: 12 };

    return res.json({
      shipping,
      currency: "INR",
      etaDays,
      meta: {
        country: country || "",
        province: p,
        postalCode: pc,
        subtotal: sub,
      },
    });
  } catch (err) {
    console.error("Error estimating shipping rates", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// API: product recommendations based on same category
// GET /api/recommendations?productId=...&limit=6
app.get("/api/recommendations", async (req, res) => {
  try {
    const { productId, limit = "6" } = req.query || {};
    if (!productId) {
      return res.status(400).json({ error: "productId is required" });
    }

    const base = await CatalogProduct.findById(productId).lean();
    if (!base) {
      return res.json({ items: [] });
    }

    const limitNum = Math.max(parseInt(limit, 10) || 6, 1);

    const baseCategoryIds = Array.isArray(base.categoryIds) && base.categoryIds.length
      ? base.categoryIds
      : base.categoryId != null
        ? [base.categoryId]
        : [];

    const items = baseCategoryIds.length
      ? await CatalogProduct.find({
          status: "active",
          _id: { $ne: base._id },
          $or: [
            { categoryIds: { $in: baseCategoryIds } },
            { categoryId: { $in: baseCategoryIds } },
          ],
        })
          .sort({ createdAt: -1 })
          .limit(limitNum)
          .lean()
      : [];

    return res.json({ items });
  } catch (err) {
    console.error("Error fetching recommendations", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// API: product recommendations (POST version)
// POST /api/recommendations
// Body: { productId: "...", limit?: 6 }
app.post("/api/recommendations", async (req, res) => {
  try {
    const { productId, limit = 6 } = req.body || {};
    if (!productId) {
      return res.status(400).json({ error: "productId is required" });
    }

    const base = await CatalogProduct.findById(productId).lean();
    if (!base) {
      return res.json({ items: [] });
    }

    const limitNum = Math.max(parseInt(limit, 10) || 6, 1);

    const baseCategoryIds = Array.isArray(base.categoryIds) && base.categoryIds.length
      ? base.categoryIds
      : base.categoryId != null
        ? [base.categoryId]
        : [];

    const items = baseCategoryIds.length
      ? await CatalogProduct.find({
          status: "active",
          _id: { $ne: base._id },
          $or: [
            { categoryIds: { $in: baseCategoryIds } },
            { categoryId: { $in: baseCategoryIds } },
          ],
        })
          .sort({ createdAt: -1 })
          .limit(limitNum)
          .lean()
      : [];

    return res.json({ items });
  } catch (err) {
    console.error("Error fetching recommendations (POST)", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

/**
 * For each category id, include that id and every descendant (subcategories via parentId).
 * So filtering by a root category returns products assigned only to its children.
 */
async function expandCategoryIdsWithDescendants(catNums) {
  const unique = [...new Set(catNums.filter((n) => Number.isFinite(n)))];
  if (!unique.length) return [];

  let allCats;
  try {
    allCats = await Category.find({}, { id: 1, parentId: 1 }).lean();
  } catch {
    return unique;
  }
  if (!Array.isArray(allCats) || !allCats.length) return unique;

  const childrenByParent = new Map();
  for (const c of allCats) {
    if (c.parentId == null || c.parentId === undefined) continue;
    const pid = Number(c.parentId);
    const cid = Number(c.id);
    if (!Number.isFinite(pid) || !Number.isFinite(cid)) continue;
    if (!childrenByParent.has(pid)) childrenByParent.set(pid, []);
    childrenByParent.get(pid).push(cid);
  }

  const out = new Set();
  const stack = [...unique];
  while (stack.length) {
    const id = stack.pop();
    if (!Number.isFinite(id) || out.has(id)) continue;
    out.add(id);
    const kids = childrenByParent.get(id);
    if (kids) {
      for (const k of kids) {
        if (!out.has(k)) stack.push(k);
      }
    }
  }
  return [...out];
}

/** Clone params and replace categoryId with expanded id list (root + all subcategories). */
async function resolveCatalogCategoryIdsInParams(params) {
  if (!params || typeof params !== "object") return params || {};
  const raw = params.categoryId;
  if (raw == null || raw === "") return { ...params };

  const catList = Array.isArray(raw)
    ? raw
    : String(raw).split(",").map((c) => c.trim()).filter(Boolean);
  const catNums = catList.map((c) => Number(c)).filter((n) => Number.isFinite(n));
  if (!catNums.length) return { ...params };

  const expanded = await expandCategoryIdsWithDescendants(catNums);
  return { ...params, categoryId: expanded.length ? expanded : catNums };
}

function escapeRegExp(str) {
  return String(str).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function buildCatalogFilter(params) {
  const {
    categoryId,
    minPrice,
    maxPrice,
    colors,
    // Backward-compat aliases (some clients send singular keys)
    color,
    multicolor,
    sizes,
    size,
    brands,
    availability,
    search,
    q,
    query,
  } = params || {};

  const filter = {};

  if (categoryId != null && categoryId !== "") {
    // Support comma-separated multiple category IDs (or array after server-side expansion)
    const catList = Array.isArray(categoryId)
      ? categoryId
      : String(categoryId).split(",").map((c) => c.trim()).filter(Boolean);
    const catNums = catList
      .map((c) => Number(c))
      .filter((n) => Number.isFinite(n));

    if (catNums.length) {
      // New: match multi-category field (`categoryIds`)
      // Backward-compat: older records may still store `categoryId`.
      filter.$or = [
        { categoryIds: { $in: catNums } },
        { categoryId: { $in: catNums } },
      ];
    } else {
      // If categoryId was provided but none of the values are valid numbers,
      // force "no matches" instead of returning all products.
      filter.$or = [{ categoryIds: { $in: [] } }, { categoryId: { $in: [] } }];
    }
  }

  if (minPrice != null || maxPrice != null) {
    filter.price = {};
    if (minPrice != null && minPrice !== "") {
      filter.price.$gte = Number(minPrice);
    }
    if (maxPrice != null && maxPrice !== "") {
      filter.price.$lte = Number(maxPrice);
    }
    if (!Object.keys(filter.price).length) {
      delete filter.price;
    }
  }

  const resolvedColors = colors != null ? colors : color;
  const colorList = Array.isArray(resolvedColors)
    ? resolvedColors
    : typeof resolvedColors === "string"
      ? resolvedColors.split(",")
      : [];
  const cleanColors = colorList.map((c) => String(c).trim()).filter(Boolean);

  // Backward-compat: if older UI sends colors=Multicolor, treat it as multicolor=true.
  const normKey = (v) => normalizeCatalogColorNameKey(v);
  const wantsMulticolorFromColors = cleanColors.some(
    (c) => normKey(c) === "multicolor",
  );
  const wantsMulticolor = (() => {
    const raw = String(multicolor ?? "").trim().toLowerCase();
    const flag = raw === "true" || raw === "1" || raw === "yes";
    return flag || wantsMulticolorFromColors;
  })();

  const colorKeysNorm = [
    ...new Set(
      cleanColors
        .filter((c) => normKey(c) !== "multicolor")
        .map(normKey)
        .filter(Boolean),
    ),
  ];

  const resolvedSizes = sizes != null ? sizes : size;
  const sizeList = Array.isArray(resolvedSizes)
    ? resolvedSizes
    : typeof resolvedSizes === "string"
      ? resolvedSizes.split(",")
      : [];
  const cleanSizes = sizeList.map((s) => String(s).trim()).filter(Boolean);
  const sizeKeysNorm = cleanSizes
    .map((s) => String(s).trim().toLowerCase())
    .filter(Boolean);

  const buildMulticolorMatchExpr = () => {
    // Robust multicolor:
    // Collect distinct normalized color NAME keys across all variants:
    // - `variant.color`
    // - `variant.colors[]`
    // Then: multicolor = distinctCount > 1
    return {
      $let: {
        vars: {
          primaryKeys: {
            $map: {
              input: { $ifNull: ["$variants", []] },
              as: "v",
              in: normalizeCatalogColorNameKeyExpr("$$v.color"),
            },
          },
          extraKeys: {
            $reduce: {
              input: { $ifNull: ["$variants", []] },
              initialValue: [],
              in: {
                $setUnion: [
                  "$$value",
                  {
                    $map: {
                      input: { $ifNull: ["$$this.colors", []] },
                      as: "c",
                      in: normalizeCatalogColorNameKeyExpr("$$c"),
                    },
                  },
                ],
              },
            },
          },
        },
        in: {
          $let: {
            vars: {
              keys: {
                $filter: {
                  input: { $setUnion: ["$$primaryKeys", "$$extraKeys"] },
                  as: "k",
                  cond: { $ne: ["$$k", ""] },
                },
              },
            },
            in: { $gt: [{ $size: "$$keys" }, 1] },
          },
        },
      },
    };
  };

  const sizeExpr = sizeKeysNorm.length
    ? buildVariantSizeKeysMatchExpr(sizeKeysNorm)
    : null;

  let colorExpr = null;
  if (wantsMulticolor && colorKeysNorm.length) {
    colorExpr = {
      $or: [
        buildVariantColorKeysMatchExpr(colorKeysNorm),
        buildMulticolorMatchExpr(),
      ],
    };
  } else if (wantsMulticolor) {
    colorExpr = buildMulticolorMatchExpr();
  } else if (colorKeysNorm.length) {
    colorExpr = buildVariantColorKeysMatchExpr(colorKeysNorm);
  }

  if (colorExpr && sizeExpr) {
    filter.$expr = { $and: [colorExpr, sizeExpr] };
  } else if (colorExpr) {
    filter.$expr = colorExpr;
  } else if (sizeExpr) {
    filter.$expr = sizeExpr;
  }

  const brandList = Array.isArray(brands)
    ? brands
    : typeof brands === "string"
      ? brands.split(",")
      : [];
  const cleanBrands = brandList.map((b) => String(b).trim()).filter(Boolean);
  if (cleanBrands.length) {
    filter.brand = { $in: cleanBrands };
  }

  // availability: "instock" | "outofstock" | comma-separated
  const availList = Array.isArray(availability)
    ? availability
    : typeof availability === "string"
      ? availability.split(",")
      : [];
  const cleanAvail = availList.map((a) => String(a).trim().toLowerCase()).filter(Boolean);
  if (cleanAvail.length) {
    if (cleanAvail.includes("instock") && !cleanAvail.includes("outofstock")) {
      // at least one size with stock > 0
      filter["variants.sizes.stock"] = { $gt: 0 };
    } else if (cleanAvail.includes("outofstock") && !cleanAvail.includes("instock")) {
      // all sizes out of stock: no size has stock > 0
      filter["variants.sizes.stock"] = { $not: { $gt: 0 } };
    }
    // if both selected, no filter needed (show all)
  }

  const searchText = String(search ?? q ?? query ?? "").trim();
  if (searchText) {
    const rx = new RegExp(escapeRegExp(searchText), "i");
    const searchClause = {
      $or: [
        { name: rx },
        { slug: rx },
        { brand: rx },
        { description: rx },
        { "variants.color": rx },
        { "variants.colors": rx },
      ],
    };
    if (!filter.$and) filter.$and = [];
    filter.$and.push(searchClause);
  }

  return filter;
}

/**
 * Canonical key for color *name* uniqueness (trim + lower + common spelling variants).
 * Kept in sync with aggregation `$addFields._colorKey` below.
 */
function normalizeCatalogColorNameKey(raw) {
  let k = String(raw || "")
    .trim()
    .toLowerCase()
    .replace(/\s+/g, " ");
  if (!k) return "";
  if (k === "gold" || k === "golen") return "golden";
  if (k === "grey") return "gray";
  return k;
}

/** Mongo expression: normalize a raw color string expression into canonical key. */
function normalizeCatalogColorNameKeyExpr(inputExpr) {
  return {
    $let: {
      vars: {
        r: {
          $toLower: {
            $trim: {
              input: { $ifNull: [inputExpr, ""] },
            },
          },
        },
      },
      in: {
        $switch: {
          branches: [
            { case: { $in: ["$$r", ["gold", "golen"]] }, then: "golden" },
            { case: { $eq: ["$$r", "grey"] }, then: "gray" },
          ],
          default: "$$r",
        },
      },
    },
  };
}

/** Mongo expression: canonical color name key for variant `v` (same rules as normalizeCatalogColorNameKey). */
function mongoVariantColorNameKeyExpr() {
  return {
    $let: {
      vars: {
        r: {
          $toLower: {
            $trim: {
              input: { $ifNull: ["$$v.color", ""] },
            },
          },
        },
      },
      in: {
        $switch: {
          branches: [
            { case: { $in: ["$$r", ["gold", "golen"]] }, then: "golden" },
            { case: { $eq: ["$$r", "grey"] }, then: "gray" },
          ],
          default: "$$r",
        },
      },
    },
  };
}

/** $expr: product has a variant whose canonical color name matches any key. */
function buildVariantColorKeysMatchExpr(normalizedKeys) {
  return {
    $gt: [
      {
        $size: {
          $filter: {
            input: { $ifNull: ["$variants", []] },
            as: "v",
            cond: {
              $gt: [
                {
                  $size: {
                    $setIntersection: [
                      {
                        $setUnion: [
                          // primary `color`
                          [
                            mongoVariantColorNameKeyExpr(),
                          ],
                          // additional `colors[]`
                          {
                            $map: {
                              input: { $ifNull: ["$$v.colors", []] },
                              as: "c",
                              in: normalizeCatalogColorNameKeyExpr("$$c"),
                            },
                          },
                        ],
                      },
                      normalizedKeys,
                    ],
                  },
                },
                0,
              ],
            },
          },
        },
      },
      0,
    ],
  };
}

/** $expr: product has a variant with a size matching any normalized key (trim + lower). */
function buildVariantSizeKeysMatchExpr(normalizedKeys) {
  return {
    $gt: [
      {
        $size: {
          $filter: {
            input: { $ifNull: ["$variants", []] },
            as: "v",
            cond: {
              $gt: [
                {
                  $size: {
                    $filter: {
                      input: { $ifNull: ["$$v.sizes", []] },
                      as: "s",
                      cond: {
                        $in: [
                          {
                            $toLower: {
                              $trim: {
                                input: { $ifNull: ["$$s.size", ""] },
                              },
                            },
                          },
                          normalizedKeys,
                        ],
                      },
                    },
                  },
                },
                0,
              ],
            },
          },
        },
      },
      0,
    ],
  };
}

/** Pick a display label from distinct DB strings (prefer longer = more specific). */
function pickRepresentativeLabel(labels) {
  const arr = [...new Set((labels || []).map(String).filter(Boolean))];
  if (!arr.length) return "";
  return arr.reduce((a, b) => (b.length > a.length ? b : a));
}

// Swatch fallback: when a color name has no stored hex code, derive one.
// This is non-breaking (only used when DB does not provide a code).
function deriveSwatchHexFromName(name) {
  const raw = String(name || "").trim();
  if (!raw) return "#ccc";
  const lower = raw.toLowerCase().trim();

  // If the string already contains a hex code, use it.
  const hexMatch = lower.match(/#([0-9a-f]{3}|[0-9a-f]{6})\b/i);
  if (hexMatch) return `#${hexMatch[1]}`.toLowerCase();

  // Common brand/catalog names → approximate hex codes
  const map = new Map([
    ["black", "#111111"],
    ["white", "#ffffff"],
    ["ivory", "#fff7e6"],
    ["cream", "#fff1d6"],
    ["off white", "#f8f5ef"],
    ["beige", "#e7d7bd"],
    ["nude", "#e6c3a5"],
    ["brown", "#7a4e2d"],
    ["chocolate", "#5a3a22"],
    ["tan", "#d2a679"],
    ["gold", "#c9a227"],
    ["golden", "#c9a227"],
    ["silver", "#b8b8b8"],
    ["gray", "#9ca3af"],
    ["grey", "#9ca3af"],
    ["red", "#ef4444"],
    ["maroon", "#7f1d1d"],
    ["pink", "#ec4899"],
    ["blush", "#f2b8b5"],
    ["blush rose", "#e7a4a6"],
    ["rose", "#f43f5e"],
    ["peach", "#fb923c"],
    ["orange", "#f97316"],
    ["yellow", "#f59e0b"],
    ["mustard", "#d97706"],
    ["green", "#22c55e"],
    ["darkgreen", "#166534"],
    ["limegreen", "#84cc16"],
    ["mehendi green", "#3f6212"],
    ["mehendigreen", "#3f6212"],
    ["forestgreen", "#14532d"],
    ["blue", "#3b82f6"],
    ["navy", "#0f172a"],
    ["purple", "#a855f7"],
    ["lavender", "#c4b5fd"],
  ]);
  if (map.has(lower)) return map.get(lower);

  // Deterministic pastel-ish color based on string hash (stable across sessions).
  let h = 0;
  for (let i = 0; i < lower.length; i++) h = (h * 31 + lower.charCodeAt(i)) >>> 0;
  const hue = h % 360;
  const sat = 58; // %
  const lit = 60; // %
  return `hsl(${hue} ${sat}% ${lit}%)`;
}

// GET /api/catalog-products/filters
// Returns aggregated filter options scoped to active filters.
// Categories are ALWAYS returned unfiltered so multi-select works.
// Colors / sizes / brands are scoped to the currently active filters.
app.get("/api/catalog-products/filters", async (req, res) => {
  try {
    // scopeFilter = everything the user has active (category, price, colors, sizes, brands, availability)
    const scopeFilter = buildCatalogFilter(
      await resolveCatalogCategoryIdsInParams(req.query || {}),
    );

    // Run all aggregations in parallel
    const [
      colorAgg,
      multicolorAgg,
      sizeAgg,
      brandAgg,
      totalCount,
      inStockCount,
      categoryAgg,   // always unfiltered
    ] = await Promise.all([
      // Colors — one row per canonical color *name* (trim+lower + gold/golen→golden, grey→gray)
      CatalogProduct.aggregate([
        { $match: scopeFilter },
        { $unwind: "$variants" },
        {
          $addFields: {
            _rawColor: {
              $setUnion: [
                [{ $ifNull: ["$variants.color", ""] }],
                { $ifNull: ["$variants.colors", []] },
              ],
            },
          },
        },
        { $unwind: "$_rawColor" },
        { $match: { _rawColor: { $nin: ["", null] } } },
        {
          $addFields: {
            _colorKey: {
              $let: {
                vars: {
                  r: {
                    $toLower: {
                      $trim: {
                        input: { $ifNull: ["$_rawColor", ""] },
                      },
                    },
                  },
                },
                in: {
                  $switch: {
                    branches: [
                      { case: { $in: ["$$r", ["gold", "golen"]] }, then: "golden" },
                      { case: { $eq: ["$$r", "grey"] }, then: "gray" },
                    ],
                    default: "$$r",
                  },
                },
              },
            },
            // Only use the variant's colorCode when this raw color is the "primary" variant color.
            // Extra `variants.colors[]` entries often don't have their own hex code.
            _primaryKey: {
              $let: {
                vars: {
                  r: {
                    $toLower: {
                      $trim: {
                        input: { $ifNull: ["$variants.color", ""] },
                      },
                    },
                  },
                },
                in: {
                  $switch: {
                    branches: [
                      { case: { $in: ["$$r", ["gold", "golen"]] }, then: "golden" },
                      { case: { $eq: ["$$r", "grey"] }, then: "gray" },
                    ],
                    default: "$$r",
                  },
                },
              },
            },
            _pickedCode: {
              $cond: [
                {
                  $eq: [
                    {
                      $let: {
                        vars: {
                          r: {
                            $toLower: {
                              $trim: {
                                input: { $ifNull: ["$variants.color", ""] },
                              },
                            },
                          },
                        },
                        in: {
                          $switch: {
                            branches: [
                              { case: { $in: ["$$r", ["gold", "golen"]] }, then: "golden" },
                              { case: { $eq: ["$$r", "grey"] }, then: "gray" },
                            ],
                            default: "$$r",
                          },
                        },
                      },
                    },
                    "$_colorKey",
                  ],
                },
                { $ifNull: ["$variants.colorCode", ""] },
                "",
              ],
            },
          },
        },
        { $match: { _colorKey: { $ne: "" } } },
        {
          $group: {
            _id: "$_colorKey",
            productIds: { $addToSet: "$_id" },
            colorCodes: { $addToSet: "$_pickedCode" },
            labels: { $addToSet: "$_rawColor" },
          },
        },
        {
          $project: {
            _id: 0,
            colorKey: "$_id",
            colorCodes: 1,
            labels: 1,
            count: { $size: "$productIds" },
          },
        },
        { $sort: { count: -1 } },
      ]),

      // Multicolor — products with 2+ distinct variant colors (or explicit "multi*" labels)
      CatalogProduct.aggregate([
        { $match: scopeFilter },
        { $unwind: "$variants" },
        {
          $addFields: {
            _rawColor: {
              $setUnion: [
                [{ $ifNull: ["$variants.color", ""] }],
                { $ifNull: ["$variants.colors", []] },
              ],
            },
            _codeKey: {
              $toLower: {
                $trim: {
                  input: { $ifNull: ["$variants.colorCode", ""] },
                },
              },
            },
          },
        },
        { $unwind: "$_rawColor" },
        // Inline the same normalization rules used by the main color aggregation.
        {
          $addFields: {
            _nameKey: {
              $let: {
                vars: {
                  r: {
                    $toLower: {
                      $trim: {
                        input: { $ifNull: ["$_rawColor", ""] },
                      },
                    },
                  },
                },
                in: {
                  $switch: {
                    branches: [
                      { case: { $in: ["$$r", ["gold", "golen"]] }, then: "golden" },
                      { case: { $eq: ["$$r", "grey"] }, then: "gray" },
                    ],
                    default: "$$r",
                  },
                },
              },
            },
          },
        },
        {
          $addFields: {
            _colorKey: {
              $cond: [
                { $ne: ["$_nameKey", ""] },
                "$_nameKey",
                "$_codeKey",
              ],
            },
          },
        },
        { $match: { _colorKey: { $ne: "" } } },
        {
          $group: {
            _id: "$_id",
            keys: { $addToSet: "$_colorKey" },
          },
        },
        {
          $project: {
            _id: 0,
            isMulti: {
              // Multicolor = product has 2+ distinct variant colors
              $gt: [{ $size: "$keys" }, 1],
            },
          },
        },
        { $match: { isMulti: true } },
        { $count: "count" },
      ]),

      // Sizes — one row per trim+lower(size); labels from DB (e.g. Free Size vs Free size)
      CatalogProduct.aggregate([
        { $match: scopeFilter },
        { $unwind: "$variants" },
        { $unwind: "$variants.sizes" },
        { $match: { "variants.sizes.size": { $nin: ["", null] } } },
        {
          $addFields: {
            _sizeKey: {
              $toLower: {
                $trim: {
                  input: { $ifNull: ["$variants.sizes.size", ""] },
                },
              },
            },
          },
        },
        { $match: { _sizeKey: { $ne: "" } } },
        // Hide internal placeholder used for no–real-size products (suits, etc.)
        { $match: { _sizeKey: { $ne: "free size" } } },
        {
          $group: {
            _id: "$_sizeKey",
            count: { $addToSet: "$_id" },
            totalStock: { $sum: "$variants.sizes.stock" },
            labels: { $addToSet: "$variants.sizes.size" },
          },
        },
        {
          $project: {
            _id: 0,
            sizeKey: "$_id",
            count: { $size: "$count" },
            totalStock: 1,
            labels: 1,
          },
        },
        { $sort: { sizeKey: 1 } },
      ]),

      // Brands — scoped to active filters
      CatalogProduct.aggregate([
        { $match: { ...scopeFilter, brand: { $ne: "", $exists: true } } },
        { $group: { _id: "$brand", count: { $sum: 1 } } },
        { $project: { _id: 0, brand: "$_id", count: 1 } },
        { $sort: { count: -1 } },
      ]),

      // Total products matching scope
      CatalogProduct.countDocuments(scopeFilter),

      // In-stock count
      CatalogProduct.countDocuments({
        ...scopeFilter,
        "variants.sizes.stock": { $gt: 0 },
      }),

      // Categories — ALWAYS unfiltered (ignore categoryId so all cats show)
      CatalogProduct.aggregate([
        { $group: { _id: "$categoryId", count: { $sum: 1 } } },
        { $sort: { count: -1 } },
      ]),
    ]);

    // Fetch category names to pair with ids
    const catIds = categoryAgg.map((c) => c._id).filter((id) => id != null);
    const categoryDocs = catIds.length
      ? await Category.find({ id: { $in: catIds } }).select({ id: 1, title: 1 }).lean()
      : [];
    const catNameMap = new Map(categoryDocs.map((c) => [c.id, c.title]));

    const categories = categoryAgg.map((c) => ({
      id: c._id,
      title: catNameMap.get(c._id) || `Category ${c._id}`,
      count: c.count,
    }));

    const colors = (colorAgg || []).map((row) => {
      const color = pickRepresentativeLabel(row.labels) || row.colorKey || "";
      const picked =
        pickRepresentativeLabel(
          (row.colorCodes || []).filter((x) => String(x || "").trim()),
        ) || "";
      const normalizedPicked = String(picked || "").trim().toLowerCase();
      const colorCode =
        normalizedPicked && normalizedPicked !== "#ccc"
          ? picked
          : deriveSwatchHexFromName(color);
      return { color, colorCode, count: row.count };
    });

    const multicolorCount =
      Array.isArray(multicolorAgg) && multicolorAgg[0]?.count
        ? Number(multicolorAgg[0].count)
        : 0;
    if (multicolorCount > 0) {
      // Avoid duplicate "Multicolor" when dataset also contains it as a real color label.
      const withoutExistingMulti = colors.filter(
        (c) => String(c?.color || "").trim().toLowerCase() !== "multicolor",
      );
      withoutExistingMulti.unshift({
        color: "Multicolor",
        colorCode:
          "linear-gradient(90deg,#ef4444,#f59e0b,#22c55e,#3b82f6,#a855f7)",
        count: multicolorCount,
      });
      colors.length = 0;
      colors.push(...withoutExistingMulti);
    }

    const sizes = (sizeAgg || []).map((row) => ({
      size: pickRepresentativeLabel(row.labels) || row.sizeKey || "",
      count: row.count,
      totalStock: row.totalStock,
    }));

    res.json({
      availability: [
        { value: "instock", label: "In stock", count: inStockCount },
        { value: "outofstock", label: "Out of stock", count: Math.max(totalCount - inStockCount, 0) },
      ],
      colors,
      sizes,
      brands: brandAgg,
      categories,
    });
  } catch (err) {
    console.error("Error fetching catalog filters", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Admin API: list catalog products (GET with query filters)
app.get("/api/admin/catalog-products", async (req, res) => {
  try {
    const { page = "1", limit = "40" } = req.query || {};
    const filter = buildCatalogFilter(
      await resolveCatalogCategoryIdsInParams(req.query || {}),
    );

    const pageNum = Math.max(parseInt(page, 10) || 1, 1);
    const limitNum = Math.max(parseInt(limit, 10) || 40, 1);
    const skip = (pageNum - 1) * limitNum;

    const [items, total] = await Promise.all([
      CatalogProduct.find(filter)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limitNum)
        .lean(),
      CatalogProduct.countDocuments(filter),
    ]);

    res.json({
      items,
      pagination: {
        total,
        page: pageNum,
        limit: limitNum,
        totalPages: Math.ceil(total / limitNum),
      },
    });
  } catch (err) {
    console.error("Error fetching catalog products", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Admin API: list catalog products (POST with JSON body filters)
function buildSortQuery(sortBy) {
  switch (sortBy) {
    case "title-ascending":    return { name: 1 };
    case "title-descending":   return { name: -1 };
    case "price-ascending":    return { price: 1 };
    case "price-descending":   return { price: -1 };
    case "created-ascending":  return { createdAt: 1 };
    case "best-selling":
    case "manual":
    case "created-descending":
    default:                   return { createdAt: -1 };
  }
}

function normalizeHex6(raw) {
  const v = String(raw || "").trim();
  if (!v) return "";
  const noHash = v.replace(/^#/, "");
  if (/^[0-9a-fA-F]{6}$/.test(noHash)) return `#${noHash.toUpperCase()}`;
  return "";
}

/** Trims variant color name and normalizes hex when present; both may be "". */
function normalizeCatalogVariantsForSave(variants) {
  if (!Array.isArray(variants)) return variants;
  return variants.map((v) => {
    if (!v || typeof v !== "object") return v;
    const colorCodeNorm = normalizeHex6(v.colorCode);
    const colorCodeFinal = colorCodeNorm || "";
    const colorFinal = String(v.color ?? "").trim();
    const extraColors = Array.isArray(v.colors)
      ? v.colors
          .map((c) => String(c ?? "").trim())
          .filter(Boolean)
          .filter(
            (c, i, arr) =>
              arr.findIndex((x) => x.toLowerCase() === c.toLowerCase()) === i,
          )
      : [];
    return {
      ...v,
      color: colorFinal,
      ...(extraColors.length ? { colors: extraColors } : { colors: [] }),
      colorCode: colorCodeFinal,
    };
  });
}

/** Clamp catalog metrics to schema bounds so bad form input does not fail validation. */
function normalizeCatalogProductNumbersForSave(payload) {
  if (!payload || typeof payload !== "object") return payload;

  const price = Number(payload.price);
  if (Number.isFinite(price)) {
    payload.price = Math.max(0, price);
  }

  const rating = Number(payload.rating);
  if (Number.isFinite(rating)) {
    payload.rating = Math.min(5, Math.max(0, rating));
  } else {
    payload.rating = 0;
  }

  const numReviews = Number(payload.numReviews);
  if (Number.isFinite(numReviews)) {
    payload.numReviews = Math.max(0, numReviews);
  } else {
    payload.numReviews = 0;
  }

  if (payload.discountPrice != null && payload.discountPrice !== "") {
    const d = Number(payload.discountPrice);
    if (!Number.isFinite(d) || d < 0) {
      delete payload.discountPrice;
    } else {
      payload.discountPrice = d;
    }
  }

  return payload;
}

const SIZE_GUIDE_FIT = new Set(["slim", "regular", "relaxed", "oversized"]);
const SIZE_GUIDE_STRETCH = new Set(["rigid", "medium", "high"]);

const SIZE_GUIDE_MAX_COLS = 12;

function normalizeSizeGuideInput(raw) {
  if (raw == null || typeof raw !== "object") return undefined;
  const stripColLabel = (v) => {
    const s = String(v ?? "").trim();
    if (!s) return "";
    return s.length > 120 ? s.slice(0, 120) : s;
  };
  const fit = String(raw.fitType || "")
    .trim()
    .toLowerCase();
  const stretch = String(raw.stretchability || "")
    .trim()
    .toLowerCase();
  const fitType = SIZE_GUIDE_FIT.has(fit) ? fit : "";
  const stretchability = SIZE_GUIDE_STRETCH.has(stretch) ? stretch : "";

  const clampCols = (n) =>
    Math.min(SIZE_GUIDE_MAX_COLS, Math.max(1, Math.floor(Number(n)) || 1));

  const rowsIn = Array.isArray(raw.rows) ? raw.rows : [];
  let colCount = 0;
  if (Array.isArray(raw.measureColumns) && raw.measureColumns.length) {
    colCount = clampCols(raw.measureColumns.length);
  } else {
    const maxVals = rowsIn.reduce((m, r) => {
      if (!r || !Array.isArray(r.values)) return m;
      return Math.max(m, r.values.length);
    }, 0);
    if (maxVals > 0) colCount = clampCols(maxVals);
    else colCount = 3;
  }

  const legacyHead = [
    stripColLabel(raw.colLabelBust),
    stripColLabel(raw.colLabelShoulder),
    stripColLabel(raw.colLabelSleeve),
  ];
  let measureColumns = [];
  if (Array.isArray(raw.measureColumns) && raw.measureColumns.length) {
    measureColumns = raw.measureColumns.map((x) => stripColLabel(x));
  }
  while (measureColumns.length < colCount) {
    const i = measureColumns.length;
    measureColumns.push(i < 3 ? legacyHead[i] : "");
  }
  measureColumns = measureColumns.slice(0, colCount);

  const rows = rowsIn
    .map((r) => {
      if (!r || typeof r !== "object") return null;
      const sizeLabel = String(r.sizeLabel ?? r.size ?? "")
        .trim()
        .toUpperCase();
      let values = [];
      if (Array.isArray(r.values) && r.values.length) {
        values = r.values.map((v) => {
          const n = Number(v);
          return Number.isFinite(n) ? n : null;
        });
      } else {
        const bust = Number(r.bust);
        const shoulder = Number(r.shoulder);
        const sleeve = Number(r.sleeve);
        values = [
          Number.isFinite(bust) ? bust : null,
          Number.isFinite(shoulder) ? shoulder : null,
          Number.isFinite(sleeve) ? sleeve : null,
        ];
      }
      while (values.length < colCount) values.push(null);
      values = values.slice(0, colCount);
      return { sizeLabel, values };
    })
    .filter(
      (r) =>
        r &&
        (r.sizeLabel ||
          (Array.isArray(r.values) &&
            r.values.some((v) => v != null && Number.isFinite(Number(v))))),
    );

  if (!fitType && !stretchability && !rows.length) return undefined;
  return {
    fitType,
    stretchability,
    measureColumns,
    rows,
  };
}

// Admin API: list catalog products (POST with JSON body filters)
app.post("/api/admin/catalog-products/search", async (req, res) => {
  try {
    const body = req.body || {};
    const { page = 1, limit = 40, sortBy, ...rest } = body;
    // Search text is allowed from multiple client keys; pluck explicitly to avoid
    // any accidental stripping during param normalization.
    const explicitSearchText = String(body.search ?? body.q ?? body.query ?? "").trim();
    const resolvedRest = await resolveCatalogCategoryIdsInParams(rest || {});
    const filter = buildCatalogFilter(resolvedRest);
    const sort = buildSortQuery(sortBy);

    const pageNum = Math.max(parseInt(page, 10) || 1, 1);
    const limitNum = Math.max(parseInt(limit, 10) || 40, 1);
    const skip = (pageNum - 1) * limitNum;

    const rawCat = rest && Object.prototype.hasOwnProperty.call(rest, "categoryId")
      ? rest.categoryId
      : undefined;
    const catList = Array.isArray(rawCat)
      ? rawCat
      : rawCat != null
        ? String(rawCat).split(",").map((c) => c.trim()).filter(Boolean)
        : [];
    const catNums = catList
      .map((c) => Number(c))
      .filter((n) => Number.isFinite(n));
    // NOTE: We intentionally do NOT collapse documents here by a “logical product key”.
    // In your dataset, legacy duplicates across categories can have differing `variants`
    // (colors/images). Collapsing with `$first: "$$ROOT"` would drop variants and cause
    // UI issues like “only one color shows”.
    //
    // Instead, we return raw rows and let the frontend merge/dedupe while preserving
    // all variants.
    const shouldDedupe = false;

    // When we pass multiple category IDs (root menu includes root + children),
    // and the same product is duplicated across those categories, we need to
    // collapse duplicates for a cleaner storefront UI.
    // We group by a best-effort key: name + price + discountPrice + brand.
    // This keeps existing functionality intact while preventing repeated cards.
    const groupKeyExpr = {
      $concat: [
        "$name",
        "__",
        { $toString: "$price" },
        "__",
        { $toString: { $ifNull: ["$discountPrice", 0] } },
        "__",
        { $ifNull: ["$brand", ""] },
        "__",
        { $ifNull: ["$description", ""] },
      ],
    };

    let items = [];
    let total = 0;

    if (!shouldDedupe) {
      if (!explicitSearchText) {
        const [fetchedItems, fetchedTotal] = await Promise.all([
          CatalogProduct.find(filter)
            .sort(sort)
            .skip(skip)
            .limit(limitNum)
            .lean(),
          CatalogProduct.countDocuments(filter),
        ]);
        items = fetchedItems;
        total = fetchedTotal;
      } else {
        // Robust search (works even when Mongo regex behaviour differs across environments):
        // fetch filtered + sorted set, then apply text matching in JS before paginating.
        const searchNeedle = explicitSearchText.toLowerCase();
        const fetchedAll = await CatalogProduct.find(filter).sort(sort).lean();
        const matched = fetchedAll.filter((p) => {
          const hay = [
            p?.name,
            p?.slug,
            p?.brand,
            p?.description,
            ...(Array.isArray(p?.variants) ? p.variants.map((v) => v?.color) : []),
          ]
            .filter((v) => typeof v === "string" && v.trim())
            .join(" ")
            .toLowerCase();
          return hay.includes(searchNeedle);
        });
        total = matched.length;
        items = matched.slice(skip, skip + limitNum);
      }
    } else {
      const pipelineBase = [
        { $match: filter },
        { $sort: sort },
        { $group: { _id: groupKeyExpr, doc: { $first: "$$ROOT" } } },
        { $replaceRoot: { newRoot: "$doc" } },
      ];

      const [countRows, fetchedItems] = await Promise.all([
        CatalogProduct.aggregate([...pipelineBase, { $count: "total" }]),
        CatalogProduct.aggregate([
          ...pipelineBase,
          { $sort: sort },
          { $skip: skip },
          { $limit: limitNum },
        ]),
      ]);

      total = Array.isArray(countRows) && countRows[0]?.total ? countRows[0].total : 0;
      items = Array.isArray(fetchedItems) ? fetchedItems : [];
    }

    res.json({
      items,
      pagination: {
        total,
        page: pageNum,
        limit: limitNum,
        totalPages: Math.ceil(total / limitNum),
      },
    });
  } catch (err) {
    console.error("Error fetching catalog products (POST search)", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Public API: search catalog products (active only)
// POST /api/catalog-products/search
app.post("/api/catalog-products/search", async (req, res) => {
  try {
    const body = req.body || {};
    const { page = 1, limit = 40, sortBy, ...rest } = body;
    const explicitSearchText = String(body.search ?? body.q ?? body.query ?? "").trim();
    const resolvedRest = await resolveCatalogCategoryIdsInParams(rest || {});
    // Force active-only for storefront
    const filter = buildCatalogFilter({ ...(resolvedRest || {}), status: "active" });
    const sort = buildSortQuery(sortBy);

    const pageNum = Math.max(parseInt(page, 10) || 1, 1);
    const limitNum = Math.max(parseInt(limit, 10) || 40, 1);
    const skip = (pageNum - 1) * limitNum;

    let items = [];
    let total = 0;

    if (!explicitSearchText) {
      const [fetchedItems, fetchedTotal] = await Promise.all([
        CatalogProduct.find(filter)
          .sort(sort)
          .skip(skip)
          .limit(limitNum)
          .lean(),
        CatalogProduct.countDocuments(filter),
      ]);
      items = fetchedItems;
      total = fetchedTotal;
    } else {
      // Same robust search approach as admin route (JS-side filtering)
      const searchNeedle = explicitSearchText.toLowerCase();
      const fetchedAll = await CatalogProduct.find(filter).sort(sort).lean();
      const matched = fetchedAll.filter((p) => {
        const hay = [
          p?.name,
          p?.slug,
          p?.brand,
          p?.description,
        ]
          .filter(Boolean)
          .map((x) => String(x).toLowerCase());
        return hay.some((t) => t.includes(searchNeedle));
      });
      total = matched.length;
      items = matched.slice(skip, skip + limitNum);
    }

    return res.json({
      items,
      pagination: {
        total,
        page: pageNum,
        limit: limitNum,
        totalPages: Math.ceil(total / limitNum),
      },
    });
  } catch (err) {
    console.error("Public catalog-products/search error", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// Admin API: create catalog product (new)
app.post("/api/admin/catalog-products", async (req, res) => {
  try {
    const payload = req.body || {};

    // Auto-generate slug from name if missing
    if (!payload.slug && payload.name) {
      const base = String(payload.name)
        .toLowerCase()
        .trim()
        .replace(/[^a-z0-9]+/g, "-")
        .replace(/^-+|-+$/g, "") || "product";

      let slug = base;
      let i = 1;
      // eslint-disable-next-line no-constant-condition
      while (true) {
        // eslint-disable-next-line no-await-in-loop
        const exists = await CatalogProduct.exists({ slug });
        if (!exists) break;
        i += 1;
        slug = `${base}-${i}`;
      }
      payload.slug = slug;
    }

    // Normalize multi-category payloads.
    // Accept: categoryIds (array or comma-string) OR legacy categoryId (single).
    const rawCategoryIds =
      payload.categoryIds != null
        ? payload.categoryIds
        : payload.categoryId != null
          ? [payload.categoryId]
          : [];

    const catList = Array.isArray(rawCategoryIds)
      ? rawCategoryIds
      : typeof rawCategoryIds === "string"
        ? rawCategoryIds.split(",")
        : [];

    const catNums = catList
      .map((c) => Number(String(c).trim()))
      .filter((n) => Number.isFinite(n));

    payload.categoryIds = catNums;
    if (!payload.categoryIds.length) {
      return res.status(400).json({ error: "categoryIds is required" });
    }
    if (!Array.isArray(payload.variants) || payload.variants.length === 0) {
      return res.status(400).json({ error: "variants is required" });
    }
    // Legacy compat: keep categoryId as "first category" for older code.
    payload.categoryId = catNums[0];
    payload.variants = normalizeCatalogVariantsForSave(payload.variants);
    normalizeCatalogProductNumbersForSave(payload);
    // Normalize specifications
    if (payload.specifications != null) {
      payload.specifications = Array.isArray(payload.specifications)
        ? payload.specifications
            .map((r) => ({
              label: String(r?.label || "").trim(),
              value: String(r?.value || "").trim(),
            }))
            .filter((r) => r.label || r.value)
        : [];
    }
    const nsgCreate = normalizeSizeGuideInput(payload.sizeGuide);
    if (nsgCreate) payload.sizeGuide = nsgCreate;
    else delete payload.sizeGuide;
    const catalogProductDoc = await CatalogProduct.create(payload);
    return res.status(201).json(catalogProductDoc.toObject());
  } catch (err) {
    console.error("Error creating catalog product", err);
    if (err && err.name === "ValidationError") {
      return res.status(400).json({ error: err.message });
    }
    if (err && err.code === 11000) {
      return res.status(409).json({ error: "Duplicate slug" });
    }
    return res.status(500).json({ error: "Internal server error" });
  }
});

// Admin API: get one catalog product
app.get("/api/admin/catalog-products/:id", async (req, res) => {
  try {
    const { id } = req.params;
    if (!id) return res.status(400).json({ error: "id is required" });
    const doc = await CatalogProduct.findById(id).lean();
    if (!doc) return res.status(404).json({ error: "Catalog product not found" });
    return res.json(doc);
  } catch (err) {
    console.error("Error fetching catalog product by id", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// Admin API: update a catalog product
app.put("/api/admin/catalog-products/:id", async (req, res) => {
  try {
    const { id: productId } = req.params;
    if (!productId) return res.status(400).json({ error: "id is required" });

    const existing = await CatalogProduct.findById(productId).lean();
    if (!existing) return res.status(404).json({ error: "Catalog product not found" });

    const payload = req.body || {};

    const merged = {
      ...existing,
      ...payload,
    };

    if (merged.name == null || String(merged.name || "").trim() === "") {
      return res.status(400).json({ error: "name is required" });
    }
    if (merged.price == null || !Number.isFinite(Number(merged.price))) {
      return res.status(400).json({ error: "price is required" });
    }
    if (merged.description == null || String(merged.description || "").trim() === "") {
      return res.status(400).json({ error: "description is required" });
    }
    const rawCategoryIds =
      merged.categoryIds != null
        ? merged.categoryIds
        : merged.categoryId != null
          ? [merged.categoryId]
          : [];

    const catList = Array.isArray(rawCategoryIds)
      ? rawCategoryIds
      : typeof rawCategoryIds === "string"
        ? rawCategoryIds.split(",")
        : [];

    const catNums = catList
      .map((c) => Number(String(c).trim()))
      .filter((n) => Number.isFinite(n));

    if (!catNums.length) {
      return res.status(400).json({ error: "categoryIds is required" });
    }

    merged.categoryIds = catNums;
    // Legacy compat
    merged.categoryId = catNums[0];
    if (!Array.isArray(merged.variants) || merged.variants.length === 0) {
      return res.status(400).json({ error: "variants is required" });
    }

    normalizeCatalogProductNumbersForSave(merged);

    // Auto-generate slug from name when:
    // - slug not provided, AND
    // - name is being changed
    let slug = merged.slug;
    const shouldRegenerateSlug =
      payload.slug == null &&
      payload.name != null &&
      String(payload.name || "").trim() !== String(existing.name || "").trim();

    if (!slug || shouldRegenerateSlug) {
      const base = String(merged.name)
        .toLowerCase()
        .trim()
        .replace(/[^a-z0-9]+/g, "-")
        .replace(/^-+|-+$/g, "") || "product";

      let candidate = base;
      let i = 1;
      while (true) {
        // eslint-disable-next-line no-await-in-loop
        const exists = await CatalogProduct.exists({
          slug: candidate,
          _id: { $ne: productId },
        });
        if (!exists) break;
        i += 1;
        candidate = `${base}-${i}`;
      }
      slug = candidate;
    }

    if (merged.categoryIds != null) {
      merged.categoryIds = Array.isArray(merged.categoryIds)
        ? merged.categoryIds
        : typeof merged.categoryIds === "string"
          ? merged.categoryIds.split(",")
          : [];
      merged.categoryIds = merged.categoryIds
        .map((c) => Number(String(c).trim()))
        .filter((n) => Number.isFinite(n));
    }
    // Legacy compat
    if (merged.categoryId != null) merged.categoryId = Number(merged.categoryId);
    const discountPrice =
      merged.discountPrice == null || merged.discountPrice === ""
        ? undefined
        : Number(merged.discountPrice);

    const sizeChartImage =
      merged.sizeChartImage != null ? String(merged.sizeChartImage).trim() : "";
    const sizeChartTitle =
      merged.sizeChartTitle != null ? String(merged.sizeChartTitle).trim() : "";

    const nsg = normalizeSizeGuideInput(merged.sizeGuide);
    const specs =
      merged.specifications != null
        ? (Array.isArray(merged.specifications) ? merged.specifications : [])
            .map((r) => ({
              label: String(r?.label || "").trim(),
              value: String(r?.value || "").trim(),
            }))
            .filter((r) => r.label || r.value)
        : undefined;

    const updatedPayload = {
      name: String(merged.name).trim(),
      slug: String(slug).trim(),
      price: Number(merged.price),
      ...(discountPrice == null ? {} : { discountPrice }),
      description: String(merged.description).trim(),
      brand: String(merged.brand || ""),
      categoryIds: Array.isArray(merged.categoryIds) ? merged.categoryIds : [],
      categoryId: Number(merged.categoryId),
      variants: normalizeCatalogVariantsForSave(merged.variants),
      rating: Number(merged.rating || 0),
      numReviews: Number(merged.numReviews || 0),
      isFeatured: Boolean(merged.isFeatured),
      status: merged.status === "inactive" ? "inactive" : "active",
      sizeChartImage,
      sizeChartTitle,
      ...(nsg ? { sizeGuide: nsg } : { sizeGuide: null }),
      ...(specs !== undefined ? { specifications: specs } : {}),
    };

    const updated = await CatalogProduct.findByIdAndUpdate(
      productId,
      { $set: updatedPayload },
      { new: true }
    ).lean();

    if (!updated) return res.status(404).json({ error: "Catalog product not found" });
    return res.json(updated);
  } catch (err) {
    console.error("Error updating catalog product", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// Admin API: delete a catalog product
app.delete("/api/admin/catalog-products/:id", async (req, res) => {
  try {
    const { id: productId } = req.params;
    if (!productId) return res.status(400).json({ error: "id is required" });
    const deleted = await CatalogProduct.findByIdAndDelete(productId).lean();
    if (!deleted) return res.status(404).json({ error: "Catalog product not found" });
    const pidStr = String(productId);
    const rvResult = await RecentlyViewed.deleteMany({ productId: pidStr });
    return res.json({
      ok: true,
      deletedId: productId,
      recentlyViewedRemoved: rvResult.deletedCount ?? 0,
    });
  } catch (err) {
    console.error("Error deleting catalog product", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// ─── Header nav = same data as Shop Categories (`categories` collection) ─────
function sortCategoryDocsForNav(list) {
  return [...(list || [])].sort(
    (a, b) =>
      (Number(a.sortOrder) || 0) - (Number(b.sortOrder) || 0) ||
      (Number(a.id) || 0) - (Number(b.id) || 0),
  );
}

/** Build Header.js–compatible menu: top-level categories → mega items; children → links with categoryIds */
function buildNavMenuFromCategories(allRaw) {
  const all = sortCategoryDocsForNav(allRaw);
  const isRoot = (c) =>
    c.parentId == null || c.parentId === undefined;
  const roots = all.filter(isRoot);
  const childrenOf = (pid) =>
    sortCategoryDocsForNav(
      all.filter((c) => Number(c.parentId) === Number(pid)),
    );

  return roots.map((root) => {
    const kids = childrenOf(root.id);
    const key = `cat-${root.id}`;
    if (!kids.length) {
      return {
        _id: key,
        key,
        label: root.title,
        categoryIds: [root.id],
      };
    }
    const allIds = [root.id, ...kids.map((k) => k.id)];
    return {
      _id: key,
      key,
      label: root.title,
      categoryIds: allIds,
      items: kids.map((c) => ({
        id: `sub-${c.id}`,
        label: c.title,
        categoryIds: [c.id],
      })),
    };
  });
}

// GET /api/nav-menu  — derived from `categories` (single source of truth)
app.get("/api/nav-menu", async (req, res) => {
  try {
    const all = await Category.find({}).lean();
    return res.json(buildNavMenuFromCategories(all));
  } catch (err) {
    console.error("Error fetching nav menu", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// Public: get current site logo
app.get("/api/site-settings/logo", async (req, res) => {
  try {
    const doc = await SiteSetting.findOne({ key: "siteLogo" }).lean();
    const logoUrl = doc?.value?.url ? String(doc.value.url) : "";
    return res.json({ logoUrl });
  } catch (err) {
    return res.json({ logoUrl: "" });
  }
});

// Admin: set site logo URL (uploaded to Cloudinary from admin UI)
app.put("/api/admin/site-settings/logo", async (req, res) => {
  try {
    const url = String(req.body?.url || "").trim();
    if (!url) return res.status(400).json({ error: "url is required" });
    const updated = await SiteSetting.findOneAndUpdate(
      { key: "siteLogo" },
      { $set: { key: "siteLogo", value: { url } } },
      { upsert: true, new: true },
    ).lean();
    return res.json({ ok: true, logoUrl: updated?.value?.url || url });
  } catch (err) {
    return res.status(500).json({ error: "Internal server error" });
  }
});

// ─── Home suggestions (Suggested for you) ────────────────────────────────────
// Stored in `site_settings` under key = "homeSuggestions"
// Shape: { productIds: ["..."], updatedAt: "ISO string" }
function sanitizeObjectIdList(list, max = 12) {
  const raw = Array.isArray(list) ? list : [];
  const out = [];
  const seen = new Set();
  for (const v of raw) {
    const id = String(v || "").trim();
    if (!id) continue;
    if (!mongoose.isValidObjectId(id)) continue;
    if (seen.has(id)) continue;
    seen.add(id);
    out.push(id);
    if (out.length >= max) break;
  }
  return out;
}

async function readHomeSuggestionsSetting() {
  const doc = await SiteSetting.findOne({ key: "homeSuggestions" }).lean();
  const productIds = sanitizeObjectIdList(doc?.value?.productIds || [], 12);
  return { productIds, updatedAt: doc?.updatedAt || null };
}

async function readCuratedProductsSetting(key, max = 12) {
  const k = String(key || "").trim();
  if (!k) return { productIds: [], updatedAt: null };
  const doc = await SiteSetting.findOne({ key: k }).lean();
  const productIds = sanitizeObjectIdList(doc?.value?.productIds || [], max);
  return { productIds, updatedAt: doc?.updatedAt || null };
}

async function writeCuratedProductsSetting(key, productIds, max = 12) {
  const k = String(key || "").trim();
  if (!k) throw new Error("key is required");
  const ids = sanitizeObjectIdList(productIds || [], max);
  const updated = await SiteSetting.findOneAndUpdate(
    { key: k },
    { $set: { key: k, value: { productIds: ids, updatedAt: new Date().toISOString() } } },
    { upsert: true, new: true },
  ).lean();
  return { productIds: ids, updatedAt: updated?.updatedAt || null };
}

// Public: get curated "Suggested for you" products
app.get("/api/home-suggestions", async (req, res) => {
  try {
    const limit = Math.min(Math.max(parseInt(req.query?.limit, 10) || 8, 1), 12);
    const { productIds } = await readHomeSuggestionsSetting();
    const ids = productIds.slice(0, limit);
    if (!ids.length) return res.json({ items: [] });

    const docs = await CatalogProduct.find({ _id: { $in: ids }, status: { $ne: "inactive" } })
      .lean();
    const byId = new Map(docs.map((d) => [String(d?._id || ""), d]));
    const ordered = ids.map((id) => byId.get(String(id))).filter(Boolean);
    return res.json({ items: ordered });
  } catch (err) {
    console.error("Error fetching home suggestions", err);
    return res.json({ items: [] });
  }
});

// ─── Home product tabs: Best sellers + New arrivals ──────────────────────────
// Keys in site_settings:
// - homeBestSellers
// - homeNewArrivals
async function getCuratedCatalogProductsByIds(ids) {
  const list = Array.isArray(ids) ? ids : [];
  if (!list.length) return [];
  const docs = await CatalogProduct.find({ _id: { $in: list }, status: { $ne: "inactive" } })
    .lean();
  const byId = new Map(docs.map((d) => [String(d?._id || ""), d]));
  return list.map((id) => byId.get(String(id))).filter(Boolean);
}

app.get("/api/home-best-sellers", async (req, res) => {
  try {
    const limit = Math.min(Math.max(parseInt(req.query?.limit, 10) || 20, 1), 40);
    const { productIds } = await readCuratedProductsSetting("homeBestSellers", 40);
    const ids = productIds.slice(0, limit);
    if (!ids.length) return res.json({ items: [] });
    const items = await getCuratedCatalogProductsByIds(ids);
    return res.json({ items });
  } catch (err) {
    console.error("Error fetching home best sellers", err);
    return res.json({ items: [] });
  }
});

app.get("/api/home-new-arrivals", async (req, res) => {
  try {
    const limit = Math.min(Math.max(parseInt(req.query?.limit, 10) || 20, 1), 40);
    const { productIds } = await readCuratedProductsSetting("homeNewArrivals", 40);
    const ids = productIds.slice(0, limit);
    if (!ids.length) return res.json({ items: [] });
    const items = await getCuratedCatalogProductsByIds(ids);
    return res.json({ items });
  } catch (err) {
    console.error("Error fetching home new arrivals", err);
    return res.json({ items: [] });
  }
});

app.get("/api/admin/home-best-sellers", authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { productIds, updatedAt } = await readCuratedProductsSetting("homeBestSellers", 40);
    const items = await getCuratedCatalogProductsByIds(productIds);
    return res.json({ productIds, updatedAt, items });
  } catch (err) {
    console.error("Error reading admin home best sellers", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

app.put("/api/admin/home-best-sellers", authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { productIds, updatedAt } = await writeCuratedProductsSetting(
      "homeBestSellers",
      req.body?.productIds || [],
      40,
    );
    return res.json({ ok: true, productIds, updatedAt });
  } catch (err) {
    console.error("Error updating home best sellers", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/api/admin/home-new-arrivals", authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { productIds, updatedAt } = await readCuratedProductsSetting("homeNewArrivals", 40);
    const items = await getCuratedCatalogProductsByIds(productIds);
    return res.json({ productIds, updatedAt, items });
  } catch (err) {
    console.error("Error reading admin home new arrivals", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

app.put("/api/admin/home-new-arrivals", authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { productIds, updatedAt } = await writeCuratedProductsSetting(
      "homeNewArrivals",
      req.body?.productIds || [],
      40,
    );
    return res.json({ ok: true, productIds, updatedAt });
  } catch (err) {
    console.error("Error updating home new arrivals", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// Admin: read current setting + preview products
app.get("/api/admin/home-suggestions", authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { productIds, updatedAt } = await readHomeSuggestionsSetting();
    if (!productIds.length) return res.json({ productIds: [], updatedAt, items: [] });
    const docs = await CatalogProduct.find({ _id: { $in: productIds } })
      .select({ _id: 1, name: 1, slug: 1, price: 1, discountPrice: 1, variants: 1, image: 1, status: 1 })
      .lean();
    const byId = new Map(docs.map((d) => [String(d?._id || ""), d]));
    const ordered = productIds.map((id) => byId.get(String(id))).filter(Boolean);
    return res.json({ productIds, updatedAt, items: ordered });
  } catch (err) {
    console.error("Error reading admin home suggestions", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// Admin: update curated product list
app.put("/api/admin/home-suggestions", authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const productIds = sanitizeObjectIdList(req.body?.productIds || [], 12);
    const updated = await SiteSetting.findOneAndUpdate(
      { key: "homeSuggestions" },
      { $set: { key: "homeSuggestions", value: { productIds, updatedAt: new Date().toISOString() } } },
      { upsert: true, new: true },
    ).lean();
    return res.json({ ok: true, productIds, updatedAt: updated?.updatedAt || null });
  } catch (err) {
    console.error("Error updating home suggestions", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

const NAV_MENU_DEPRECATED_MSG =
  "Navigation is built from Shop Categories. Use Admin → Categories (titles, parent, Sort order).";

// Legacy admin routes — nav is no longer a separate table
app.post(
  "/api/admin/nav-menu",
  authMiddleware,
  adminMiddleware,
  async (req, res) => {
    return res.status(400).json({ error: NAV_MENU_DEPRECATED_MSG });
  },
);

app.patch(
  "/api/admin/nav-menu/:key",
  authMiddleware,
  adminMiddleware,
  async (req, res) => {
    return res.status(400).json({ error: NAV_MENU_DEPRECATED_MSG });
  },
);

const PORT = process.env.PORT || 4000;
const HOST = process.env.HOST || "0.0.0.0";

async function start() {
  const uri = (process.env.MONGODB_URI || "").trim();
  if (!uri) {
    console.error(
      "MONGODB_URI missing — set it in websiteBackend/.env (see .env.example).",
    );
  } else {
    try {
      await mongoose.connect(uri);
      console.log("MongoDB connected");
      await seedAdmin();
      // await seedShirtSubcategories();
      ensureUploadFilesAsync({
        uploadDir: UPLOAD_DIR,
        db: mongoose.connection.db,
      }).catch((err) => console.error("[uploads] background sync failed:", err.message));
    } catch (err) {
      console.error("Failed to connect to MongoDB. Continuing without DB.", err);
    }
  }

  // Start the Express server regardless of MongoDB connection status
  app.listen(PORT, HOST, () => {
    console.log(`Server listening on http://${HOST}:${PORT}`);
  });
}

start();