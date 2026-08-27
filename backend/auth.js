const crypto = require("crypto");

function validatePassword(password) {
  const errors = [];
  if (!password || password.length < 8) errors.push("At least 8 characters");
  if (!/[A-Z]/.test(password || "")) errors.push("1 uppercase letter");
  if (!/[0-9]/.test(password || "")) errors.push("1 number");
  if (!/[^A-Za-z0-9]/.test(password || "")) errors.push("1 special character");
  return { valid: errors.length === 0, errors };
}

const LOGIN_MAX_ATTEMPTS = 5;
const LOGIN_LOCKOUT_MS = 5 * 60 * 1000;
const JWT_TTL_SECONDS = 15 * 60;

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function loginFailureState(user) {
  const now = Date.now();
  if (user.lockedUntil && now < user.lockedUntil) {
    return {
      locked: true,
      retryAfterSeconds: Math.ceil((user.lockedUntil - now) / 1000),
    };
  }
  return { locked: false };
}

function recordLoginFailure(user) {
  const attempts = Number(user.failedLoginAttempts || 0) + 1;
  const lockedUntil = attempts >= LOGIN_MAX_ATTEMPTS
    ? Date.now() + LOGIN_LOCKOUT_MS
    : null;

  return {
    failedLoginAttempts: attempts,
    lockedUntil,
  };
}

function clearLoginFailures() {
  return {
    failedLoginAttempts: 0,
    lockedUntil: null,
  };
}

function base64url(value) {
  return Buffer.from(value).toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

function base64urlDecode(value) {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/")
    + "=".repeat((4 - (value.length % 4)) % 4);
  return Buffer.from(padded, "base64").toString("utf8");
}

function getJwtSecret() {
  return process.env.JWT_SECRET
}

function signJwt(payload, expiresInSeconds = JWT_TTL_SECONDS) {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "HS256", typ: "JWT" };
  const body = {
    ...payload,
    iat: now,
    exp: now + expiresInSeconds,
  };

  const encodedHeader = base64url(JSON.stringify(header));
  const encodedBody = base64url(JSON.stringify(body));
  const unsigned = `${encodedHeader}.${encodedBody}`;
  const signature = crypto.createHmac("sha256", getJwtSecret())
    .update(unsigned)
    .digest("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");

  return `${unsigned}.${signature}`;
}

function verifyJwt(token) {
  if (!token) return { valid: false, reason: "missing_token" };

  const parts = String(token).split(".");
  if (parts.length !== 3) return { valid: false, reason: "invalid_token" };

  const unsigned = `${parts[0]}.${parts[1]}`;
  const expected = crypto.createHmac("sha256", getJwtSecret())
    .update(unsigned)
    .digest("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");

  const a = Buffer.from(parts[2]);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return { valid: false, reason: "invalid_signature" };
  }

  try {
    const payload = JSON.parse(base64urlDecode(parts[1]));
    if (!payload.exp || Math.floor(Date.now() / 1000) >= payload.exp) {
      return { valid: false, reason: "expired" };
    }
    return { valid: true, payload };
  } catch {
    return { valid: false, reason: "invalid_payload" };
  }
}

module.exports = {
  validatePassword,
  normalizeEmail,
  LOGIN_MAX_ATTEMPTS,
  LOGIN_LOCKOUT_MS,
  JWT_TTL_SECONDS,
  loginFailureState,
  recordLoginFailure,
  clearLoginFailures,
  signJwt,
  verifyJwt,
};
