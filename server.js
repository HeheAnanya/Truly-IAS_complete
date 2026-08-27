require("dotenv").config();

const path = require("path");
const crypto = require("crypto");
const express = require("express");
const bcrypt = require("bcryptjs");
const store = require("./backend/store");
const otp = require("./backend/otp");
const auth = require("./backend/auth");
const cors = require("cors");
const QRCode = require("qrcode");

const app = express();

const allowedOrigins = (process.env.FRONTEND_ORIGINS)
    .split(",")
    .map((origin) => origin.trim())
    .filter(Boolean);

app.use(cors({
    origin(origin, callback) {
        if (!origin || allowedOrigins.includes(origin)) return callback(null, true);
        return callback(new Error(`CORS origin not allowed: ${origin}`));
    },
    credentials: true,
}));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

function maskEmail(email) {
    const [name, domain] = email.split("@");
    if (!domain) return email;
    const visible = name.slice(0, 2);
    return `${visible}${"*".repeat(Math.max(name.length - 2, 1))}@${domain}`;
}

function maskMobile(mobile) {
    return String(mobile || "").replace(/\d(?=\d{2})/g, "*");
}

function parseCookies(req) {
    const header = req.headers.cookie || "";
    return header.split(";").reduce((cookies, part) => {
        const index = part.indexOf("=");
        if (index === -1) return cookies;
        const key = part.slice(0, index).trim();
        const value = decodeURIComponent(part.slice(index + 1).trim());
        cookies[key] = value;
        return cookies;
    }, {});
}

function setSessionCookie(res, session) {
    const parts = [
        `secureid_session=${encodeURIComponent(session.sessionId)}`,
        "Path=/",
        "HttpOnly",
        "SameSite=Lax",
    ];
    if (process.env.NODE_ENV === "production") parts.push("Secure");
    if (session.rememberMe) parts.push("Max-Age=2592000");
    res.setHeader("Set-Cookie", parts.join("; "));
}

function clearSessionCookie(res) {
    res.setHeader("Set-Cookie", "secureid_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0");
}

async function getSessionUser(req) {
    const sessionId = parseCookies(req).secureid_session;
    const session = store.getSession(sessionId);
    if (!session) return null;
    return store.getUserById(session.userId);
}

async function requireSession(req, res, next) {
    const user = await getSessionUser(req);
    if (!user) return res.status(401).json({ authenticated: false, error: "Authentication required." });
    req.user = user;
    next();
}

async function issueOtpChallenge({ userId, channel, purpose, destination }) {
    const code = otp.generateOtp();
    const challenge = await store.createChallenge({
        userId,
        channel,
        purpose,
        otpHash: otp.hashOtp(code),
        expiresAt: otp.otpExpiryTimestamp(),
        maxAttempts: otp.OTP_MAX_ATTEMPTS,
    });
    otp.deliverOtpSimulated({ channel, destination, code, purpose });
    return { ...challenge, devOtp: code };
}


// ---------------- TOTP / Authenticator helpers ----------------
const TOTP_STEP_SECONDS = 30;
const TOTP_DIGITS = 6;

function base32Encode(buffer) {
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let bits = 0;
    let value = 0;
    let output = "";
    for (const byte of buffer) {
        value = (value << 8) | byte;
        bits += 8;
        while (bits >= 5) {
            output += alphabet[(value >>> (bits - 5)) & 31];
            bits -= 5;
        }
    }
    if (bits > 0) output += alphabet[(value << (5 - bits)) & 31];
    return output;
}

function base32Decode(input) {
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    const clean = String(input || "").toUpperCase().replace(/=+$/, "");
    let bits = 0;
    let value = 0;
    const out = [];
    for (const char of clean) {
        const index = alphabet.indexOf(char);
        if (index < 0) throw new Error("Invalid base32 secret");
        value = (value << 5) | index;
        bits += 5;
        if (bits >= 8) {
            out.push((value >>> (bits - 8)) & 255);
            bits -= 8;
        }
    }
    return Buffer.from(out);
}

function generateTotpCode(secret, counter) {
    const key = base32Decode(secret);
    const buffer = Buffer.alloc(8);
    buffer.writeBigUInt64BE(BigInt(counter));
    const digest = crypto.createHmac("sha1", key).update(buffer).digest();
    const offset = digest[digest.length - 1] & 15;
    const binary = ((digest[offset] & 127) << 24) |
        ((digest[offset + 1] & 255) << 16) |
        ((digest[offset + 2] & 255) << 8) |
        (digest[offset + 3] & 255);
    return String(binary % (10 ** TOTP_DIGITS)).padStart(TOTP_DIGITS, "0");
}

function verifyTotpCode(secret, code) {
    const normalized = String(code || "").replace(/\D/g, "");
    if (normalized.length !== TOTP_DIGITS) return false;
    const counter = Math.floor(Date.now() / 1000 / TOTP_STEP_SECONDS);
    return [-1, 0, 1].some((offset) => crypto.timingSafeEqual(
        Buffer.from(generateTotpCode(secret, counter + offset)),
        Buffer.from(normalized)
    ));
}

function makeTotpSecret() {
    return base32Encode(crypto.randomBytes(20));
}

async function makeTotpSetup(user) {
    const secret = makeTotpSecret();
    const issuer = "SecureID";
    const account = encodeURIComponent(user.email);
    const otpauth = `otpauth://totp/${encodeURIComponent(issuer)}:${account}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=${TOTP_DIGITS}&period=${TOTP_STEP_SECONDS}`;
    const qrDataUrl = await QRCode.toDataURL(otpauth, { width: 220, margin: 1 });
    return { secret, otpauth, qrDataUrl };
}

// ---------------- Registration (Part 1) ----------------
app.post("/api/register", async (req, res) => {
    const { fullName, email, mobile, password, agreeTerms } = req.body || {};
    if (!fullName || !email || !mobile || !password) return res.status(400).json({ error: "All fields are required." });
    if (!agreeTerms) return res.status(400).json({ error: "You must agree to the Terms & Conditions." });
    if (!/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ error: "Enter a valid email address." });
    if (await store.getUserByEmail(email)) return res.status(409).json({ error: "An account with this email already exists." });

    const { valid, errors } = auth.validatePassword(password);
    if (!valid) return res.status(400).json({ error: "Password does not meet requirements.", details: errors });

    let user;
    try {
        user = await store.createUser({
            fullName,
            email,
            mobile,
            passwordHash: bcrypt.hashSync(password, 10),
        });
    } catch (error) {
        if (error.code === "EMAIL_EXISTS") return res.status(409).json({ error: "An account with this email already exists." });
        throw error;
    }

    const challenge = await issueOtpChallenge({
        userId: user.id,
        channel: "email",
        purpose: "register-email",
        destination: user.email,
    });

    return res.status(201).json({
        userId: user.id,
        challengeId: challenge.challengeId,
        maskedEmail: maskEmail(user.email),
        expiresInSeconds: otp.OTP_TTL_MS / 1000,
        devOtp: challenge.devOtp,
    });
});

app.post("/api/send-email-otp", async (req, res) => {
    const { userId, purpose = "register-email" } = req.body || {};
    const user = await store.getUserById(userId);
    if (!user) return res.status(404).json({ error: "User not found." });
    const challenge = await issueOtpChallenge({ userId: user.id, channel: "email", purpose, destination: user.email });
    return res.json({ challengeId: challenge.challengeId, maskedEmail: maskEmail(user.email), expiresInSeconds: otp.OTP_TTL_MS / 1000, devOtp: challenge.devOtp });
});

app.post("/api/verify-email-otp", async (req, res) => {
    const { challengeId, code } = req.body || {};
    const challenge = await store.getChallenge(challengeId);
    const result = otp.verifyChallenge(challenge, code);
    if (challenge) await store.saveChallenge(challenge);
    if (!result.ok) return res.status(400).json({ verified: false, reason: result.reason, attemptsLeft: result.attemptsLeft });

    const user = await store.getUserById(challenge.userId);
    if (challenge.purpose === "register-email") await store.updateUser(user.id, { emailVerified: true });
    return res.json({ verified: true, next: "sms-otp" });
});

app.post("/api/send-sms-otp", async (req, res) => {
    const { userId, purpose = "register-sms" } = req.body || {};
    const user = await store.getUserById(userId);
    if (!user) return res.status(404).json({ error: "User not found." });
    const challenge = await issueOtpChallenge({ userId: user.id, channel: "sms", purpose, destination: user.mobile });
    return res.json({ challengeId: challenge.challengeId, maskedMobile: maskMobile(user.mobile), expiresInSeconds: otp.OTP_TTL_MS / 1000, devOtp: challenge.devOtp });
});

app.post("/api/verify-sms-otp", async (req, res) => {
    const { challengeId, code } = req.body || {};
    const challenge = await store.getChallenge(challengeId);
    const result = otp.verifyChallenge(challenge, code);
    if (challenge) await store.saveChallenge(challenge);
    if (!result.ok) return res.status(400).json({ verified: false, reason: result.reason, attemptsLeft: result.attemptsLeft });

    const user = await store.getUserById(challenge.userId);
    if (challenge.purpose === "register-sms") {
        await store.updateUser(user.id, { mobileVerified: true, mfaEnabled: true, mfaMethod: "email" });
    }
    return res.json({ verified: true, mfaEnabled: true, next: "registration-complete" });
});

// ---------------- Login (Part 2) ----------------
app.post("/api/login", async (req, res) => {
    const { email, password, rememberMe = false } = req.body || {};
    const normalizedEmail = auth.normalizeEmail(email);
    if (!normalizedEmail || !password) return res.status(400).json({ error: "Email and password are required." });

    const user = await store.getUserByEmail(normalizedEmail);
    if (!user) return res.status(401).json({ error: "Invalid email or password." });

    const lockState = auth.loginFailureState(user);
    if (lockState.locked) {
        return res.status(423).json({ error: `Account temporarily locked. Try again in ${lockState.retryAfterSeconds}s.`, retryAfterSeconds: lockState.retryAfterSeconds });
    }

    const passwordMatches = await bcrypt.compare(password, user.passwordHash);
    if (!passwordMatches) {
        await store.updateUser(user.id, auth.recordLoginFailure(user));
        const afterFailure = await store.getUserById(user.id);
        const state = auth.loginFailureState(afterFailure);
        if (state.locked) return res.status(423).json({ error: "Too many failed attempts. Account temporarily locked.", retryAfterSeconds: state.retryAfterSeconds });
        const left = auth.LOGIN_MAX_ATTEMPTS - Number(afterFailure.failedLoginAttempts || 0);
        return res.status(401).json({ error: "Invalid email or password.", attemptsLeft: Math.max(0, left) });
    }

    await store.updateUser(user.id, auth.clearLoginFailures());

    if (!user.emailVerified || !user.mobileVerified || !user.mfaEnabled) {
        return res.status(403).json({
            mfaRequired: false,
            error: "MFA is not enabled for this account. Complete registration first.",
        });
    }

    const ticket = store.createLoginTicket({ userId: user.id, rememberMe });
    return res.json({
        authenticated: false,
        mfaRequired: true,
        loginTicket: ticket.ticket,
        methods: user.totpSecret ? ["email", "sms", "totp"] : ["email", "sms", "totp-setup"],
        maskedEmail: maskEmail(user.email),
        maskedMobile: maskMobile(user.mobile),
    });
});

app.post("/api/login/send-otp", async (req, res) => {
    const { loginTicket, method } = req.body || {};
    if (!loginTicket || !["email", "sms", "totp"].includes(method)) return res.status(400).json({ error: "Choose a valid verification method." });

    const ticket = store.getLoginTicket(loginTicket);
    if (!ticket) return res.status(401).json({ error: "Login attempt expired. Please log in again." });

    const user = await store.getUserById(ticket.userId);
    if (!user || !user.mfaEnabled) return res.status(403).json({ error: "MFA is not enabled." });

    if (method === "totp") {
        if (!user.totpSecret) {
            return res.json({ setupRequired: true, method: "totp-setup" });
        }
        return res.json({ mfaRequired: true, method: "totp", userId: user.id, expiresInSeconds: TOTP_STEP_SECONDS });
    }

    const channel = method;
    const destination = channel === "email" ? user.email : user.mobile;
    const challenge = await issueOtpChallenge({
        userId: user.id,
        channel,
        purpose: `login-${channel}`,
        destination,
    });

    return res.json({
        mfaRequired: true,
        method,
        challengeId: challenge.challengeId,
        userId: user.id,
        maskedEmail: maskEmail(user.email),
        maskedMobile: maskMobile(user.mobile),
        expiresInSeconds: otp.OTP_TTL_MS / 1000,
        devOtp: challenge.devOtp,
    });
});

app.post("/api/login/setup-totp", async (req, res) => {
    const { loginTicket } = req.body || {};
    const ticket = store.getLoginTicket(loginTicket);
    if (!ticket) return res.status(401).json({ error: "Login attempt expired. Please log in again." });

    const user = await store.getUserById(ticket.userId);
    if (!user) return res.status(401).json({ error: "User not found." });

    const setup = await makeTotpSetup(user);
    await store.updateUser(user.id, { pendingTotpSecret: setup.secret, mfaSetupAttempts: 0 });

    return res.json({
        setupRequired: true,
        qrDataUrl: setup.qrDataUrl,
        secret: setup.secret,
        issuer: "SecureID",
        account: user.email,
    });
});

app.post("/api/login/verify-totp-setup", async (req, res) => {
    const { loginTicket, code } = req.body || {};
    const ticket = store.getLoginTicket(loginTicket);
    if (!ticket) return res.status(401).json({ verified: false, reason: "login_expired" });

    const user = await store.getUserById(ticket.userId);
    if (!user || !user.pendingTotpSecret) return res.status(400).json({ verified: false, reason: "setup_not_found" });

    if (!verifyTotpCode(user.pendingTotpSecret, code)) {
        const attempts = Number(user.mfaSetupAttempts || 0) + 1;
        await store.updateUser(user.id, { mfaSetupAttempts: attempts });
        return res.status(400).json({ verified: false, reason: attempts >= 3 ? "max_attempts" : "invalid_code", attemptsLeft: Math.max(0, 3 - attempts) });
    }

    const session = store.createSession({ userId: user.id, rememberMe: ticket.rememberMe });
    await store.updateUser(user.id, {
        totpSecret: user.pendingTotpSecret,
        pendingTotpSecret: null,
        mfaSetupAttempts: 0,
        mfaEnabled: true,
        mfaMethod: "totp",
    });
    store.deleteLoginTicket(loginTicket);
    setSessionCookie(res, session);
    return res.json({ verified: true, authenticated: true, next: "dashboard" });
});

app.post("/api/verify-login-otp", async (req, res) => {
    const { challengeId, code, loginTicket, method } = req.body || {};

    if (method === "totp") {
        const ticket = store.getLoginTicket(loginTicket);
        if (!ticket) return res.status(401).json({ verified: false, reason: "login_expired" });
        const user = await store.getUserById(ticket.userId);
        if (!user || !user.totpSecret) return res.status(400).json({ verified: false, reason: "totp_not_configured" });
        if (!verifyTotpCode(user.totpSecret, code)) return res.status(400).json({ verified: false, reason: "invalid_code" });
        const session = store.createSession({ userId: user.id, rememberMe: ticket.rememberMe });
        store.deleteLoginTicket(loginTicket);
        setSessionCookie(res, session);
        return res.json({ verified: true, authenticated: true, next: "dashboard" });
    }

    const challenge = await store.getChallenge(challengeId);
    const result = otp.verifyChallenge(challenge, code);
    if (challenge) await store.saveChallenge(challenge);

    if (!result.ok) return res.status(400).json({ verified: false, reason: result.reason, attemptsLeft: result.attemptsLeft });
    if (!challenge.purpose.startsWith("login-")) return res.status(400).json({ verified: false, reason: "invalid_purpose" });

    const ticket = store.getLoginTicket(loginTicket);
    if (!ticket || ticket.userId !== challenge.userId) return res.status(401).json({ verified: false, reason: "login_expired" });

    const session = store.createSession({ userId: challenge.userId, rememberMe: ticket.rememberMe });
    store.deleteLoginTicket(loginTicket);
    setSessionCookie(res, session);

    return res.json({ verified: true, authenticated: true, next: "dashboard" });
});

// ---------------- Session authentication ----------------
app.get("/api/me", async (req, res) => {
    const user = await getSessionUser(req);
    if (!user) return res.status(401).json({ authenticated: false });
    return res.json({
        authenticated: true,
        user: {
            id: user.id,
            fullName: user.fullName,
            email: user.email,
            mobile: user.mobile,
            mfaEnabled: user.mfaEnabled,
        },
    });
});

app.post("/api/logout", (req, res) => {
    const sessionId = parseCookies(req).secureid_session;
    store.deleteSession(sessionId);
    clearSessionCookie(res);
    return res.json({ loggedOut: true });
});

// ---------------- JWT protected API ----------------
app.post("/api/token", async (req, res) => {
    const user = await getSessionUser(req);
    if (!user) return res.status(401).json({ error: "Authenticated session required." });

    const token = auth.signJwt({
        sub: user.id,
        email: user.email,
        scope: "secureid:protected",
    });

    return res.json({ token, tokenType: "Bearer", expiresInSeconds: auth.JWT_TTL_SECONDS });
});

app.get("/api/protected", async (req, res) => {
    const header = req.headers.authorization || "";
    const token = header.startsWith("Bearer ") ? header.slice(7) : null;
    const result = auth.verifyJwt(token);
    if (!result.valid) return res.status(401).json({ protected: false, reason: result.reason });

    const user = await store.getUserById(result.payload.sub);
    if (!user) return res.status(401).json({ protected: false, reason: "user_not_found" });

    return res.json({
        protected: true,
        message: "JWT validated by the backend.",
        user: { id: user.id, email: user.email, fullName: user.fullName },
    });
});

app.use((error, req, res, next) => {
    console.error("API error:", error);
    if (res.headersSent) return next(error);
    return res.status(500).json({ error: "Internal server error." });
});

app.get(/^(?!\/api\/).*/, (req, res) => {
    res.sendFile(path.join(__dirname, "public", "index.html"));
});

const PORT = process.env.PORT || 3000;
if (require.main === module) {
    app.listen(PORT, () => {
        console.log(`SecureID (Part 1 + Part 2) server running on http://localhost:${PORT}`);
    });
}

module.exports = app;
