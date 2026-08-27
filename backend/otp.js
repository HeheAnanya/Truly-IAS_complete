/**
 * OTP generation & verification — always server-side.
 *
 * Rules enforced here (per the assignment's Implementation Guidelines):
 *  - The real OTP is generated on the server with a CSPRNG, never in
 *    frontend JS.
 *  - The raw OTP is NEVER returned in any API response. Only a hash of it
 *    is stored (`otpHash` on the challenge record in lib/store.js).
 *  - OTPs are short-lived (OTP_TTL_MS) and single-use (`consumed` flag).
 *  - Verification attempts are capped (maxAttempts on the challenge).
 *  - "Delivery" is simulated by printing to the server console, since this
 *    assignment has no real email/SMS provider wired up.
 */

const crypto = require("crypto");

const OTP_TTL_MS = 2 * 60 * 1000; // 2 minutes, matches the "02:45" style timers in the mockups
const OTP_MAX_ATTEMPTS = 3;

/** Generate a random 6-digit numeric OTP using a CSPRNG (not Math.random). */
function generateOtp() {
  const n = crypto.randomInt(0, 1000000); // 0..999999
  return String(n).padStart(6, "0");
}

/** One-way hash of an OTP for storage. SHA-256 is fine for a short-lived,
 *  rate-limited, single-use 6-digit code — the OTP is never persisted in
 *  plaintext anywhere, which is the actual requirement. */
function hashOtp(code) {
  return crypto.createHash("sha256").update(String(code)).digest("hex");
}

function otpExpiryTimestamp() {
  return Date.now() + OTP_TTL_MS;
}

/**
 * Simulated delivery. In a real system this would call an email/SMS
 * provider (SES, Twilio, etc). For this assignment we log to the server
 * console so the flow is fully testable without external services.
 */
function deliverOtpSimulated({ channel, destination, code, purpose }) {
  const label = channel === "email" ? "[SIMULATED EMAIL]" : channel === "sms" ? "[SIMULATED SMS]" : "[SIMULATED AUTHENTICATOR]";
  console.log(
    `\n${label}\nTo: ${destination}\nPurpose: ${purpose}\nOTP: ${code}\n(expires in ${OTP_TTL_MS / 1000}s)\n`
  );
}

/**
 * Verify a submitted code against a challenge record.
 * Returns { ok: boolean, reason?: 'expired'|'max_attempts'|'invalid'|'consumed' }
 * Mutates the challenge (attempts, consumed) via the passed-in store update fns.
 */
function verifyChallenge(challenge, submittedCode) {
  if (!challenge) return { ok: false, reason: "not_found" };
  if (challenge.consumed) return { ok: false, reason: "consumed" };
  if (Date.now() > challenge.expiresAt) return { ok: false, reason: "expired" };
  if (challenge.attempts >= challenge.maxAttempts) return { ok: false, reason: "max_attempts" };

  challenge.attempts += 1;

  const submittedHash = hashOtp(submittedCode);
  // Constant-time compare to avoid leaking timing info about the correct hash.
  const a = Buffer.from(submittedHash);
  const b = Buffer.from(challenge.otpHash);
  const matches = a.length === b.length && crypto.timingSafeEqual(a, b);

  if (!matches) {
    if (challenge.attempts >= challenge.maxAttempts) {
      return { ok: false, reason: "max_attempts" };
    }
    return { ok: false, reason: "invalid", attemptsLeft: challenge.maxAttempts - challenge.attempts };
  }

  challenge.consumed = true;
  return { ok: true };
}

module.exports = {
  OTP_TTL_MS,
  OTP_MAX_ATTEMPTS,
  generateOtp,
  hashOtp,
  otpExpiryTimestamp,
  deliverOtpSimulated,
  verifyChallenge,
};
