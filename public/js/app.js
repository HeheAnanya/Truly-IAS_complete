const API_BASE_URL = (document.querySelector('meta[name="api-base"]')?.content || "").replace(/\/$/, "");

async function api(path, method = "GET", body) {
    const res = await fetch(API_BASE_URL + path, {
        method,
        credentials: "include",
        headers: body ? { "Content-Type": "application/json" } : undefined,
        body: body ? JSON.stringify(body) : undefined,
    });
    const data = await res.json().catch(() => ({}));
    return { ok: res.status, data };
}
const screens = document.querySelectorAll(".screen");

function showScreen(name, { pushHistory = true } = {}) {
  const screen = document.querySelector(
    `[data-screen="${name}"]`
  );
  if (!screen) {
    console.error("Screen not found:", name);
    return;
  }
  screens.forEach((s) => {
    s.classList.toggle(
      "active",
      s.dataset.screen === name
    );
  });
  updateStepper(name);
  if (pushHistory) {
    history.pushState(
      { screen: name },
      "",
      `#${name}`
    );
  }
}
function updateStepper(screenName) {
  const stepper = document.getElementById("registration-stepper");

  if (!stepper) return;

  const isLoginScreen = ["login-placeholder", "login-method", "forgot-password", "dashboard"].includes(screenName);
  stepper.style.display = isLoginScreen ? "none" : "flex";
  if (isLoginScreen) return;

  let currentStep = 1;
  if (screenName === "reg-details") {
    currentStep = 1;
  }
  else if (screenName === "otp") {
    if (otpState.channel === "sms") {
      currentStep = 3;
    } else {
      currentStep = 2;
    }
  }
  else if (
    screenName === "reg-mfa-complete"
  ) {
    currentStep = 4;
  }
  else if (
    screenName === "reg-success" ||
    screenName === "login-placeholder"
  ) {
    currentStep = 5;
  }

  const steps = stepper.querySelectorAll(".step");

  steps.forEach((step) => {
    const stepNumber = Number(step.dataset.step);

    step.classList.remove("active", "completed");

    if (stepNumber < currentStep) {
      step.classList.add("completed");
    }

    if (stepNumber === currentStep) {
      step.classList.add("active");
    }
  });
}
// ------------------------------------------------------------
// Initial screen
// ------------------------------------------------------------
const initialScreen = location.hash.replace("#", "") || "reg-details";
showScreen(initialScreen, { pushHistory: false });

// On refresh/direct navigation, never reveal a login/OTP screen if a session is active.
(async () => {
    const session = await api("/api/me");
    if (session.ok < 400 && session.data.authenticated) {
        const current = document.querySelector(".screen.active")?.dataset.screen;
        if (current !== "dashboard") {
            const loaded = await loadDashboard();
            if (loaded) protectDashboardHistory();
        }
    } else if (initialScreen === "dashboard") {
        history.replaceState({ screen: "login-placeholder" }, "", "#login-placeholder");
        showScreen("login-placeholder", { pushHistory: false });
    }
})();


// ------------------------------------------------------------
// Browser Back / Forward
// ------------------------------------------------------------

window.addEventListener("popstate", async (event) => {
  const screen = event.state?.screen || location.hash.replace("#", "") || "reg-details";

  // Never expose a previously authenticated screen by navigating back.
  if (screen !== "dashboard") {
    const session = await api("/api/me");
    const current = document.querySelector(".screen.active")?.dataset.screen;
    if (session.ok < 400 && session.data.authenticated && current === "dashboard") {
      history.pushState({ screen: "dashboard", guard: true }, "", "#dashboard");
      showScreen("dashboard", { pushHistory: false });
      return;
    }
  }

  showScreen(screen, { pushHistory: false });
});


document.querySelectorAll("[data-goto]").forEach((el) => {
  el.addEventListener("click", (e) => {
    e.preventDefault();
    const target = el.dataset.goto;
    if (target){
    showScreen(el.dataset.goto)}
  });
});



document.querySelectorAll("[data-goto-back]").forEach((el) => {
  el.addEventListener("click", (e) => {
    e.preventDefault();
    if (history.length>1){
    history.back();}
    else{
        showScreen("reg-details")
    }
  });
});

document.querySelectorAll("[data-toggle-password]").forEach((btn) => {
    btn.addEventListener("click", () => {
        const input = document.getElementById(btn.dataset.togglePassword);
        input.type = input.type === "password" ? "text" : "password";
        btn.textContent = input.type === "password" ? "👁" : "🙈";
    });
});


const regPasswordInput = document.getElementById("reg-password");
regPasswordInput.addEventListener("input", () => {
    const v = regPasswordInput.value;
    setRule("len", v.length >= 8);
    setRule("upper", /[A-Z]/.test(v));
    setRule("num", /[0-9]/.test(v));
    setRule("special", /[^A-Za-z0-9]/.test(v));
});
function setRule(rule, met) {
    document.querySelector(`#password li[data-rule="${rule}"]`).classList.toggle("met", met);
}


const otpBoxes = Array.from(document.querySelectorAll("#otp-boxes input"));
const totpSetupBoxes = Array.from(document.querySelectorAll("#totp-setup-boxes input"));
let otpState = {
    challengeId: null,
    purpose: null, // 'register-email' | 'register-sms' | 'mfa-setup'
    userId: null,
    channel: null,
    timerInterval: null,
    resendInterval: null,
    ttlSeconds: 120,
    loginTicket: null,
};

function wireOtpBoxNavigation() {
    otpBoxes.forEach((box, i) => {
        box.addEventListener("input", () => {
            box.value = box.value.replace(/\D/g, "").slice(0, 1);
            box.classList.remove("error");
            if (box.value && i < otpBoxes.length - 1) otpBoxes[i + 1].focus();
        });
        box.addEventListener("keydown", (e) => {
            if (e.key === "Backspace" && !box.value && i > 0) otpBoxes[i - 1].focus();
        });
        box.addEventListener("paste", (e) => {
            e.preventDefault();
            const digits = (e.clipboardData.getData("text").match(/\d/g) || []).slice(0, otpBoxes.length);
            digits.forEach((d, idx) => { if (otpBoxes[idx]) otpBoxes[idx].value = d; });
            const next = otpBoxes[Math.min(digits.length, otpBoxes.length - 1)];
            next.focus();
        });
    });
}
wireOtpBoxNavigation();

function wireCodeBoxes(boxes) {
    boxes.forEach((box, i) => {
        box.addEventListener("input", () => {
            box.value = box.value.replace(/\D/g, "").slice(0, 1);
            if (box.value && i < boxes.length - 1) boxes[i + 1].focus();
        });
        box.addEventListener("keydown", (e) => {
            if (e.key === "Backspace" && !box.value && i > 0) boxes[i - 1].focus();
        });
        box.addEventListener("paste", (e) => {
            e.preventDefault();
            const digits = (e.clipboardData.getData("text").match(/\d/g) || []).slice(0, boxes.length);
            digits.forEach((d, idx) => { if (boxes[idx]) boxes[idx].value = d; });
            boxes[Math.min(digits.length, boxes.length - 1)]?.focus();
        });
    });
}
wireCodeBoxes(totpSetupBoxes);

function currentOtpCode() {
    return otpBoxes.map((b) => b.value).join("");
}
function clearOtpBoxes() {
    otpBoxes.forEach((b) => { b.value = ""; b.classList.remove("error"); });
    otpBoxes[0].focus();
}
function markOtpError() {
    otpBoxes.forEach((b) => b.classList.add("error"));
}

function startOtpTimer(seconds) {
    clearInterval(otpState.timerInterval);
    clearInterval(otpState.resendInterval);
    const timerEl = document.getElementById("otp-timer");
    const timerRow = document.getElementById("otp-timer-row");
    const resendLink = document.getElementById("otp-resend-link");
    const resendCooldownEl = document.getElementById("otp-resend-cooldown");

    let remaining = seconds;
    resendLink.classList.add("disabled");
    timerRow.style.display = "";

    otpState.timerInterval = setInterval(() => {
        remaining -= 1;
        if (remaining <= 0) {
            clearInterval(otpState.timerInterval);
            timerEl.textContent = "00:00";
            timerRow.textContent = "";
            document.getElementById("otp-error").textContent = "This code has expired.";
            return;
        }
        timerEl.textContent = formatMMSS(remaining);
    }, 1000);

    let resendRemaining = Math.min(25, seconds);
    resendCooldownEl.textContent = formatMMSS(resendRemaining);
    otpState.resendInterval = setInterval(() => {
        resendRemaining -= 1;
        if (resendRemaining <= 0) {
            clearInterval(otpState.resendInterval);
            resendLink.classList.remove("disabled");
            resendCooldownEl.textContent = "";
            return;
        }
        resendCooldownEl.textContent = formatMMSS(resendRemaining);
    }, 1000);
}

function formatMMSS(totalSeconds) {
    const m = Math.floor(totalSeconds / 60).toString().padStart(2, "0");
    const s = Math.floor(totalSeconds % 60).toString().padStart(2, "0");
    return `${m}:${s}`;
}

function renderOtpScreen({ purpose, challengeId, userId, channel, destination, ttlSeconds, loginTicket = null, pushHistory = true }) {
    otpState.purpose = purpose;
    otpState.challengeId = challengeId;
    otpState.userId = userId;
    otpState.channel = channel;
    otpState.ttlSeconds = ttlSeconds || 120;
    otpState.loginTicket = loginTicket || null;

    const icon = channel === "sms" ? "📱" : channel === "totp" ? "🔑" : "✉️";
    const title = channel === "sms" ? "Verify your mobile" : channel === "totp" ? "Enter the 6-digit code" : "Verify your email";
    document.getElementById("otp-icon").textContent = icon;
    document.getElementById("otp-title").textContent = title;
    document.getElementById("otp-destination").textContent = destination || "";
    document.getElementById("otp-subtitle").style.display = channel === "totp" ? "none" : "";
    document.getElementById("otp-error").textContent = "";
    document.getElementById("otp-wrong-number").hidden = channel !== "sms";
    document.getElementById("otp-resend-link").style.display = channel === "totp" ? "none" : "";
    document.getElementById("otp-didnt-receive").style.display = channel === "totp" ? "none" : "";

    clearOtpBoxes();
    showScreen("otp",{pushHistory});
    if (channel !== "totp") startOtpTimer(otpState.ttlSeconds);
}

document.getElementById("form-otp").addEventListener("submit", async (e) => {
    e.preventDefault();
    const code = currentOtpCode();
    if (code.length !== 6) return;

    const errorEl = document.getElementById("otp-error");
    errorEl.textContent = "";

    let endpoint;
    let payload = { challengeId: otpState.challengeId, code };
    if (otpState.loginTicket) payload.loginTicket = otpState.loginTicket;

    if (otpState.purpose === "register-email") {
        endpoint = "/api/verify-email-otp";
    } else if (otpState.purpose === "register-sms") {
        endpoint = "/api/verify-sms-otp";
    } else if (otpState.purpose === "login-email" || otpState.purpose === "login-sms" || otpState.purpose === "login-totp") {
        endpoint = "/api/verify-login-otp";
        if (otpState.purpose === "login-totp") payload.method = "totp";
    } else {
        return;
    }

    const { data, ok } = await api(endpoint, "POST", payload);
    if (ok >= 400 && !data.verified) {
        markOtpError();
        if (data.reason === "expired") errorEl.textContent = "This code has expired.";
        else if (data.reason === "max_attempts") errorEl.textContent = "Maximum attempts reached. Please request a new code.";
        else errorEl.textContent = data.error || `Incorrect code. Please try again. ${data.attemptsLeft != null ? `You have ${data.attemptsLeft} attempt(s) left.` : ""}`;
        return;
    }

    if (!data.verified) {
        markOtpError();
        if (data.reason === "expired") errorEl.textContent = "This code has expired.";
        else if (data.reason === "max_attempts") errorEl.textContent = "Maximum attempts reached. Please request a new code.";
        else errorEl.textContent = `Incorrect code. Please try again. ${data.attemptsLeft != null ? `You have ${data.attemptsLeft} attempt(s) left.` : ""}`;
        return;
    }

    clearInterval(otpState.timerInterval);
    clearInterval(otpState.resendInterval);

    if (otpState.purpose === "register-email") {
        const send = await api("/api/send-sms-otp", "POST", { userId: otpState.userId, purpose: "register-sms" });
        if (send.ok >= 400) {
            errorEl.textContent = send.data.error || "Unable to send SMS code.";
            return;
        }
        console.log("📱 Registration SMS OTP:", send.data.devOtp);
        renderOtpScreen({
            purpose: "register-sms",
            challengeId: send.data.challengeId,
            userId: otpState.userId,
            channel: "sms",
            destination: send.data.maskedMobile,
            ttlSeconds: send.data.expiresInSeconds,
        });
    } else if (otpState.purpose === "register-sms") {
        showScreen("reg-mfa-complete");
    } else if (otpState.purpose === "login-email" || otpState.purpose === "login-sms") {
        const loaded = await loadDashboard();
        otpState.loginTicket = null;
        if (loaded) protectDashboardHistory();
    }
});

document.getElementById("otp-resend-link").addEventListener("click", async (e) => {
    e.preventDefault();
    if (e.currentTarget.classList.contains("disabled")) return;

    if (otpState.purpose === "register-email") {
        const { data } = await api("/api/send-email-otp", "POST", { userId: otpState.userId, purpose: "register-email" });
        console.log("🔐 Registration Email OTP (resent):", data.devOtp);
        renderOtpScreen({ purpose: "register-email", challengeId: data.challengeId, userId: otpState.userId, channel: "email", destination: data.maskedEmail, ttlSeconds: data.expiresInSeconds ,pushHistory:false});
    } else if (otpState.purpose === "register-sms") {
        const { data } = await api("/api/send-sms-otp", "POST", { userId: otpState.userId, purpose: "register-sms" });
        console.log("📱 Registration SMS OTP (resent):", data.devOtp);
        renderOtpScreen({ purpose: "register-sms", challengeId: data.challengeId, userId: otpState.userId, channel: "sms", destination: data.maskedMobile, ttlSeconds: data.expiresInSeconds });
    } else if (otpState.purpose === "login-email" || otpState.purpose === "login-sms") {
        const method = otpState.purpose === "login-email" ? "email" : "sms";
        const { data, ok } = await api("/api/login/send-otp", "POST", { loginTicket: otpState.loginTicket, method });
        if (ok >= 400) {
            document.getElementById("otp-error").textContent = data.error || "Unable to resend code.";
            return;
        }
        console.log(`🔐 Login ${method.toUpperCase()} OTP (resent):`, data.devOtp);
        renderOtpScreen({
            purpose: `login-${method}`,
            challengeId: data.challengeId,
            userId: data.userId,
            channel: method,
            destination: method === "email" ? data.maskedEmail : data.maskedMobile,
            ttlSeconds: data.expiresInSeconds,
            loginTicket: otpState.loginTicket,
        });
    }
});


document.getElementById("form-register").addEventListener("submit", async (e) => {
    e.preventDefault();
    const form = e.target;
    const errorEl = document.getElementById("register-error");
    errorEl.classList.remove("visible");

    const payload = {
        fullName: form.fullName.value.trim(),
        email: form.email.value.trim(),
        mobile: "+91 " + form.mobile.value.trim(),
        password: form.password.value,
        agreeTerms: form.agreeTerms.checked,
    };

    const { ok, data } = await api("/api/register", "POST", payload);
    if (ok >= 400) {
        errorEl.textContent = data.error || "Something went wrong. Please check your details.";
        errorEl.classList.add("visible");
        return;
    }

    console.log("🔐 Registration Email OTP:", data.devOtp);

    renderOtpScreen({
        purpose: "register-email",
        challengeId: data.challengeId,
        userId: data.userId,
        channel: "email",
        destination: data.maskedEmail,
        ttlSeconds: data.expiresInSeconds,
        pushHistory:false
    });
});



// ------------------------------------------------------------
// Part 2 — Login Journey
// ------------------------------------------------------------
let loginState = {
    loginTicket: null,
    email: null,
    rememberMe: false,
    maskedEmail: "",
    maskedMobile: "",
};

const loginForm = document.getElementById("form-login");
if (loginForm) {
    loginForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        const errorEl = document.getElementById("login-error");
        errorEl.textContent = "";

        const email = loginForm.email.value.trim();
        const password = loginForm.password.value;
        const rememberMe = loginForm.rememberMe.checked;

        if (!email || !password) {
            errorEl.textContent = "Enter your email and password.";
            return;
        }

        const { ok, data } = await api("/api/login", "POST", { email, password, rememberMe });
        if (ok >= 400) {
            errorEl.textContent = data.error || "Unable to log in.";
            return;
        }

        loginState = {
            loginTicket: data.loginTicket,
            email,
            rememberMe,
            maskedEmail: data.maskedEmail,
            maskedMobile: data.maskedMobile,
        };

        document.getElementById("login-email-destination").textContent = data.maskedEmail;
        document.getElementById("login-mobile-destination").textContent = data.maskedMobile;
        document.getElementById("method-error").textContent = "";
        showScreen("login-method");
    });
}

document.querySelectorAll("[data-login-method]").forEach((button) => {
    button.addEventListener("click", async () => {
        const method = button.dataset.loginMethod;
        const errorEl = document.getElementById("method-error");
        errorEl.textContent = "";

        if (method === "totp") {
            const response = await api("/api/login/send-otp", "POST", {
                loginTicket: loginState.loginTicket,
                method: "totp",
            });
            if (response.ok >= 400) {
                errorEl.textContent = response.data.error || "Unable to start authenticator verification.";
                return;
            }
            if (response.data.setupRequired) {
                const setup = await api("/api/login/setup-totp", "POST", { loginTicket: loginState.loginTicket });
                if (setup.ok >= 400) {
                    errorEl.textContent = setup.data.error || "Unable to set up authenticator.";
                    return;
                }
                document.getElementById("totp-qr").src = setup.data.qrDataUrl;
                document.getElementById("totp-secret").textContent = `Manual setup key: ${setup.data.secret}`;
                totpSetupBoxes.forEach((box) => { box.value = ""; });
                showScreen("totp-setup");
                totpSetupBoxes[0]?.focus();
                return;
            }
            renderOtpScreen({
                purpose: "login-totp",
                challengeId: null,
                userId: response.data.userId,
                channel: "totp",
                destination: "Authenticator app",
                ttlSeconds: response.data.expiresInSeconds,
                loginTicket: loginState.loginTicket,
            });
            return;
        }

        const { ok, data } = await api("/api/login/send-otp", "POST", {
            loginTicket: loginState.loginTicket,
            method,
        });

        if (ok >= 400) {
            errorEl.textContent = data.error || "Unable to send verification code.";
            return;
        }

        console.log(`🔐 Login ${method.toUpperCase()} OTP:`, data.devOtp);

        renderOtpScreen({
            purpose: `login-${method}`,
            challengeId: data.challengeId,
            userId: data.userId,
            channel: method,
            destination: method === "email" ? data.maskedEmail : data.maskedMobile,
            ttlSeconds: data.expiresInSeconds,
            loginTicket: loginState.loginTicket,
        });
    });
});

const totpSetupForm = document.getElementById("form-totp-setup");
if (totpSetupForm) {
    totpSetupForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        const code = totpSetupBoxes.map((box) => box.value).join("");
        const errorEl = document.getElementById("totp-setup-error");
        errorEl.textContent = "";
        if (code.length !== 6) {
            errorEl.textContent = "Enter the 6-digit code from your authenticator app.";
            return;
        }
        const response = await api("/api/login/verify-totp-setup", "POST", {
            loginTicket: loginState.loginTicket,
            code,
        });
        if (response.ok >= 400 || !response.data.verified) {
            errorEl.textContent = response.data.reason === "max_attempts"
                ? "Maximum attempts reached. Please log in again."
                : "Incorrect authenticator code. Please try again.";
            return;
        }
        showScreen("totp-success");
    });
}

document.getElementById("totp-success-continue")?.addEventListener("click", async () => {
    const loaded = await loadDashboard();
    if (loaded) {
        showScreen("dashboard");
        protectDashboardHistory();
    }
});

function protectDashboardHistory() {
    history.replaceState({ screen: "dashboard" }, "", "#dashboard");
    history.pushState({ screen: "dashboard", guard: true }, "", "#dashboard");
}

async function loadDashboard() {
    const { ok, data } = await api("/api/me");
    if (ok >= 400 || !data.authenticated) {
        showScreen("login-placeholder");
        return false;
    }
    document.getElementById("dashboard-name").textContent = data.user.fullName;
    document.getElementById("dashboard-email").textContent = data.user.email;
    document.getElementById("dashboard-mfa").textContent = data.user.mfaEnabled ? "Enabled" : "Not enabled";
    document.getElementById("dashboard-status").textContent = "Session authenticated by the backend.";
    return true;
}

const sessionCheckBtn = document.getElementById("session-check-btn");
if (sessionCheckBtn) sessionCheckBtn.addEventListener("click", loadDashboard);

const jwtCheckBtn = document.getElementById("jwt-check-btn");
if (jwtCheckBtn) {
    jwtCheckBtn.addEventListener("click", async () => {
        const status = document.getElementById("dashboard-status");
        const tokenResponse = await api("/api/token", "POST");
        if (tokenResponse.ok >= 400) {
            status.textContent = tokenResponse.data.error || "Unable to issue JWT.";
            return;
        }

        // JWT stays in memory only; never store it in localStorage.
        const protectedResponse = await fetch(API_BASE_URL + "/api/protected", {
            headers: { Authorization: `Bearer ${tokenResponse.data.token}` },
            credentials: "include",
        });
        const protectedData = await protectedResponse.json().catch(() => ({}));
        status.textContent = protectedResponse.ok
            ? "JWT validated successfully by the protected API."
            : (protectedData.reason || "JWT validation failed.");
    });
}

const logoutBtn = document.getElementById("logout-btn");
if (logoutBtn) {
    logoutBtn.addEventListener("click", async () => {
        await api("/api/logout", "POST");
        loginState = { loginTicket: null, email: null, rememberMe: false, maskedEmail: "", maskedMobile: "" };
        history.replaceState({ screen: "login-placeholder" }, "", "#login-placeholder");
        showScreen("login-placeholder", { pushHistory: false });
    });
}

if (location.hash === "#dashboard") loadDashboard();
