
const crypto = require("crypto");
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const pool = require("../config/db");
const { authenticateToken } = require("../middleware/auth");

const router = express.Router();

const COOKIE_NAME = "access_token";
const REFRESH_COOKIE_NAME = "refresh_token";

const ACCESS_TOKEN_LIFETIME = 15 * 60 * 1000;
const REFRESH_TOKEN_LIFETIME = 7 * 24 * 60 * 60 * 1000;

function cookieOptions(maxAge) {
  return {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/",
    maxAge,
  };
}

function clearAuthCookies(res) {
  const options = {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/",
  };

  res.clearCookie(COOKIE_NAME, options);
  res.clearCookie(REFRESH_COOKIE_NAME, options);
}

function getJwtSecret() {
  const secret = process.env.JWT_SECRET;

  if (!secret || secret.length < 32) {
    throw new Error("JWT_SECRET must contain at least 32 characters.");
  }

  return secret;
}

function createToken(user) {
  return jwt.sign(
    {
      tenantId: String(user.tenant_id),
      roles: [user.role],
      tokenType: "access",
    },
    getJwtSecret(),
    {
      subject: String(user.id),
      expiresIn: process.env.JWT_EXPIRES_IN || "15m",
    }
  );
}

function createRefreshToken() {
  return crypto.randomBytes(32).toString("hex");
}

function hashRefreshToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

async function issueTokens(res, user) {
  const accessToken = createToken(user);
  const refreshToken = createRefreshToken();

  await pool.query(
    `INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
     VALUES ($1, $2, $3)`,
    [
      user.id,
      hashRefreshToken(refreshToken),
      new Date(Date.now() + REFRESH_TOKEN_LIFETIME),
    ]
  );

  res.cookie(
    COOKIE_NAME,
    accessToken,
    cookieOptions(ACCESS_TOKEN_LIFETIME)
  );

  res.cookie(
    REFRESH_COOKIE_NAME,
    refreshToken,
    cookieOptions(REFRESH_TOKEN_LIFETIME)
  );
}

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function validEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function splitName(fullName, firstName, lastName) {
  const parts = String(fullName || "").trim().split(/\s+/).filter(Boolean);

  return {
    firstName: String(firstName || parts[0] || "School").trim(),
    lastName: String(lastName || parts.slice(1).join(" ") || "").trim(),
  };
}

// --------------------------------------------------
// SIGNUP
// POST /api/auth/signup
// --------------------------------------------------

router.post(["/signup", "/register-school"], async (req, res) => {
  const schoolName = String(
    req.body.schoolName || req.body.name || ""
  ).trim();

  const email = normalizeEmail(req.body.email);
  const password = req.body.password;

  const names = splitName(
    req.body.fullName,
    req.body.firstName,
    req.body.lastName
  );

  const rawCode = String(
    req.body.schoolCode || req.body.slug || schoolName
  );

  const schoolCode = rawCode
    .trim()
    .toUpperCase()
    .replace(/[^A-Z0-9]+/g, "")
    .slice(0, 20);

  if (
    schoolName.length < 2 ||
    schoolName.length > 200 ||
    !schoolCode ||
    !validEmail(email) ||
    typeof password !== "string" ||
    password.length < 6
  ) {
    return res.status(400).json({
      success: false,
      message: "Provide a valid school name, school code, email and password.",
    });
  }

  let client;

  try {
    const passwordHash = await bcrypt.hash(password, 12);

    client = await pool.connect();
    await client.query("BEGIN");

    const tenantResult = await client.query(
      `INSERT INTO tenants (school_code, school_name, email)
       VALUES ($1, $2, $3)
       RETURNING id, school_code, school_name, email, plan_status`,
      [schoolCode, schoolName, email]
    );

    const tenant = tenantResult.rows[0];

    const userResult = await client.query(
      `INSERT INTO users (
         tenant_id,
         email,
         password_hash,
         role,
         first_name,
         last_name
       )
       VALUES ($1, $2, $3, 'school_admin', $4, $5)
       RETURNING id, tenant_id, email, role, first_name, last_name`,
      [
        tenant.id,
        email,
        passwordHash,
        names.firstName,
        names.lastName,
      ]
    );

    const user = userResult.rows[0];

    await client.query("COMMIT");

    return res.status(201).json({
      success: true,
      message: "School registered successfully. Please log in.",
      school: {
        id: tenant.id,
        code: tenant.school_code,
        name: tenant.school_name,
        status: tenant.plan_status,
      },
      user: {
        id: user.id,
        tenantId: user.tenant_id,
        email: user.email,
        role: user.role,
        firstName: user.first_name,
        lastName: user.last_name,
        fullName: `${user.first_name} ${user.last_name}`.trim(),
      },
    });
  } catch (error) {
    if (client) {
      await client.query("ROLLBACK").catch(() => {});
    }

    if (error.code === "23505") {
      return res.status(409).json({
        success: false,
        message: "That school code or email already exists.",
      });
    }

    console.error("School registration failed:", error.message);

    return res.status(500).json({
      success: false,
      message: "Unable to register school.",
    });
  } finally {
    client?.release();
  }
});

// --------------------------------------------------
// LOGIN
// POST /api/auth/login
// --------------------------------------------------

router.post("/login", async (req, res) => {
  const email = normalizeEmail(req.body.email);
  const password = req.body.password;

  const schoolCode = String(
    req.body.tenantSlug || req.body.schoolCode || ""
  ).trim().toLowerCase();

  if (!validEmail(email) || typeof password !== "string" || !password) {
    return res.status(400).json({
      success: false,
      message: "Provide a valid email and password.",
    });
  }

  try {
    let result;

    if (schoolCode) {
      result = await pool.query(
        `SELECT
           u.id,
           u.tenant_id,
           u.email,
           u.password_hash,
           u.role,
           u.first_name,
           u.last_name,
           u.avatar_url,
           u.is_active,
           t.school_code,
           t.school_name,
           t.plan_status
         FROM users u
         JOIN tenants t ON t.id = u.tenant_id
         WHERE LOWER(t.school_code) = $1
           AND u.email = $2
           AND u.is_active = TRUE
         LIMIT 1`,
        [schoolCode, email]
      );
    } else {
      result = await pool.query(
        `SELECT
           u.id,
           u.tenant_id,
           u.email,
           u.password_hash,
           u.role,
           u.first_name,
           u.last_name,
           u.avatar_url,
           u.is_active,
           t.school_code,
           t.school_name,
           t.plan_status
         FROM users u
         JOIN tenants t ON t.id = u.tenant_id
         WHERE u.email = $1
           AND u.is_active = TRUE
         LIMIT 1`,
        [email]
      );
    }

    const user = result.rows[0];

    if (
      !user ||
      user.plan_status !== "active" ||
      !(await bcrypt.compare(password, user.password_hash))
    ) {
      return res.status(401).json({
        success: false,
        message: "Invalid credentials or inactive school.",
      });
    }

    await pool.query(
      "UPDATE users SET last_login_at = NOW() WHERE id = $1",
      [user.id]
    );

    await issueTokens(res, user);

    const firstName = user.first_name || "User";
    const lastName = user.last_name || "";

    return res.json({
      success: true,
      message: "Login successful.",
      user: {
        id: String(user.id),
        tenantId: String(user.tenant_id),
        email: user.email,
        role: user.role,
        roles: [user.role],
        firstName,
        lastName,
        fullName: `${firstName} ${lastName}`.trim(),
        avatarUrl: user.avatar_url || null,
      },
      school: {
        code: user.school_code,
        tenantId: String(user.tenant_id),
        name: user.school_name,
      },
    });
  } catch (error) {
    console.error("Login failed:", error.message);

    return res.status(500).json({
      success: false,
      message: "Unable to log in.",
    });
  }
});

// --------------------------------------------------
// REFRESH TOKEN
// POST /api/auth/refresh
// --------------------------------------------------

router.post("/refresh", async (req, res) => {
  const refreshToken = req.cookies?.[REFRESH_COOKIE_NAME];

  if (!refreshToken) {
    clearAuthCookies(res);

    return res.status(401).json({
      success: false,
      message: "Refresh token required. Please log in again.",
    });
  }

  let client;

  try {
    client = await pool.connect();
    await client.query("BEGIN");

    const tokenHash = hashRefreshToken(refreshToken);

    const result = await client.query(
      `SELECT
         rt.user_id,
         rt.expires_at,
         u.tenant_id,
         u.role,
         u.is_active,
         t.plan_status
       FROM refresh_tokens rt
       JOIN users u ON u.id = rt.user_id
       JOIN tenants t ON t.id = u.tenant_id
       WHERE rt.token_hash = $1
       FOR UPDATE OF rt`,
      [tokenHash]
    );

    const session = result.rows[0];

    if (
      !session ||
      new Date(session.expires_at).getTime() <= Date.now() ||
      !session.is_active ||
      session.plan_status !== "active"
    ) {
      await client.query(
        "DELETE FROM refresh_tokens WHERE token_hash = $1",
        [tokenHash]
      );

      await client.query("COMMIT");
      clearAuthCookies(res);

      return res.status(401).json({
        success: false,
        message: "Session expired or invalid. Please log in again.",
      });
    }

    const user = {
      id: session.user_id,
      tenant_id: session.tenant_id,
      role: session.role,
    };

    const newAccessToken = createToken(user);
    const newRefreshToken = createRefreshToken();

    await client.query(
      "DELETE FROM refresh_tokens WHERE token_hash = $1",
      [tokenHash]
    );

    await client.query(
      `INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
       VALUES ($1, $2, $3)`,
      [
        session.user_id,
        hashRefreshToken(newRefreshToken),
        new Date(Date.now() + REFRESH_TOKEN_LIFETIME),
      ]
    );

    await client.query("COMMIT");

    res.cookie(
      COOKIE_NAME,
      newAccessToken,
      cookieOptions(ACCESS_TOKEN_LIFETIME)
    );

    res.cookie(
      REFRESH_COOKIE_NAME,
      newRefreshToken,
      cookieOptions(REFRESH_TOKEN_LIFETIME)
    );

    return res.json({
      success: true,
      message: "Session refreshed successfully.",
    });
  } catch (error) {
    if (client) {
      await client.query("ROLLBACK").catch(() => {});
    }

    console.error("Token refresh failed:", error.message);

    return res.status(500).json({
      success: false,
      message: "Unable to refresh session.",
    });
  } finally {
    client?.release();
  }
});

// --------------------------------------------------
// LOGOUT
// POST /api/auth/logout
// --------------------------------------------------

router.post("/logout", async (req, res) => {
  const refreshToken = req.cookies?.[REFRESH_COOKIE_NAME];

  try {
    if (refreshToken) {
      await pool.query(
        "DELETE FROM refresh_tokens WHERE token_hash = $1",
        [hashRefreshToken(refreshToken)]
      );
    }

    clearAuthCookies(res);

    return res.json({
      success: true,
      message: "Logged out successfully.",
    });
  } catch (error) {
    console.error("Logout failed:", error.message);
    clearAuthCookies(res);

    return res.status(500).json({
      success: false,
      message: "Unable to complete logout.",
    });
  }
});

// --------------------------------------------------
// GET PROFILE
// GET /api/auth/me
// --------------------------------------------------

router.get("/me", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT
         u.id,
         u.tenant_id,
         u.email,
         u.role,
         u.first_name,
         u.last_name,
         u.phone,
         u.avatar_url,
         u.is_active,
         u.is_email_verified,
         t.school_name,
         t.school_code,
         t.plan_status
       FROM users u
       JOIN tenants t ON t.id = u.tenant_id
       WHERE u.id = $1 AND u.tenant_id = $2`,
      [req.user.id, req.user.tenantId]
    );

    const user = result.rows[0];

    if (!user || !user.is_active || user.plan_status !== "active") {
      clearAuthCookies(res);

      return res.status(401).json({
        success: false,
        message: "Account is inactive or unavailable.",
      });
    }

    const firstName = user.first_name || "User";
    const lastName = user.last_name || "";
    const fullName = `${firstName} ${lastName}`.trim();

    return res.json({
      success: true,
      user: {
        id: String(user.id),
        tenantId: String(user.tenant_id),
        tenant_id: user.tenant_id,
        email: user.email,
        role: user.role,
        roles: [user.role],
        first_name: firstName,
        last_name: lastName,
        firstName,
        lastName,
        full_name: fullName,
        fullName,
        phone: user.phone,
        avatar_url: user.avatar_url,
        avatarUrl: user.avatar_url,
        schoolName: user.school_name,
        school_code: user.school_code,
        is_email_verified: user.is_email_verified,
      },
    });
  } catch (error) {
    console.error("Profile lookup failed:", error.message);

    return res.status(500).json({
      success: false,
      message: "Unable to retrieve profile.",
    });
  }
});

// --------------------------------------------------
// UPDATE PROFILE
// PUT /api/auth/me
// --------------------------------------------------

router.put("/me", authenticateToken, async (req, res) => {
  try {
    const { first_name, last_name, phone, avatar_url } = req.body;

    const result = await pool.query(
      `UPDATE users
       SET first_name = COALESCE($1, first_name),
           last_name = COALESCE($2, last_name),
           phone = COALESCE($3, phone),
           avatar_url = COALESCE($4, avatar_url),
           updated_at = NOW()
       WHERE id = $5 AND tenant_id = $6
       RETURNING id, tenant_id, email, role,
                 first_name, last_name, phone, avatar_url`,
      [
        first_name || null,
        last_name || null,
        phone || null,
        avatar_url || null,
        req.user.id,
        req.user.tenantId,
      ]
    );

    const user = result.rows[0];

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found.",
      });
    }

    return res.json({
      success: true,
      message: "Profile updated successfully.",
      user: {
        ...user,
        full_name: `${user.first_name || ""} ${user.last_name || ""}`.trim(),
      },
    });
  } catch (error) {
    console.error("Update profile failed:", error.message);

    return res.status(500).json({
      success: false,
      message: "Unable to update profile.",
    });
  }
});

// --------------------------------------------------
// FORGOT PASSWORD
// POST /api/auth/forgot-password
// --------------------------------------------------

router.post("/forgot-password", async (req, res) => {
  const email = normalizeEmail(req.body.email);

  if (!validEmail(email)) {
    return res.status(400).json({
      success: false,
      message: "Valid email is required.",
    });
  }

  try {
    const otp = crypto.randomInt(100000, 1000000).toString();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

    await pool.query(
      `UPDATE users
       SET otp_code = $1, otp_expires_at = $2
       WHERE email = $3`,
      [otp, expiresAt, email]
    );

    return res.json({
      success: true,
      message: "If the account exists, an OTP has been generated.",
      otp: process.env.NODE_ENV !== "production" ? otp : undefined,
    });
  } catch (error) {
    console.error("Forgot password error:", error.message);

    return res.status(500).json({
      success: false,
      message: "Unable to process request.",
    });
  }
});

// --------------------------------------------------
// VERIFY OTP
// POST /api/auth/verify-otp
// --------------------------------------------------

router.post("/verify-otp", async (req, res) => {
  const email = normalizeEmail(req.body.email);
  const otp = String(req.body.otp || req.body.otp_code || "").trim();

  if (!validEmail(email) || !otp) {
    return res.status(400).json({
      success: false,
      message: "Email and OTP are required.",
    });
  }

  try {
    const result = await pool.query(
      `SELECT id, email
       FROM users
       WHERE email = $1
         AND otp_code = $2
         AND otp_expires_at > NOW()`,
      [email, otp]
    );

    if (!result.rows[0]) {
      return res.status(400).json({
        success: false,
        message: "Invalid or expired OTP.",
      });
    }

    const resetToken = jwt.sign(
      {
        email,
        purpose: "password_reset",
      },
      getJwtSecret(),
      { expiresIn: "10m" }
    );

    await pool.query(
      `UPDATE users
       SET otp_code = NULL, otp_expires_at = NULL
       WHERE email = $1`,
      [email]
    );

    return res.json({
      success: true,
      message: "OTP verified successfully.",
      reset_token: resetToken,
      resetToken,
    });
  } catch (error) {
    console.error("Verify OTP error:", error.message);

    return res.status(500).json({
      success: false,
      message: "Unable to verify OTP.",
    });
  }
});

// --------------------------------------------------
// RESET PASSWORD
// POST /api/auth/reset-password
// --------------------------------------------------

router.post("/reset-password", async (req, res) => {
  const resetToken = req.body.reset_token || req.body.resetToken;
  const password = req.body.password;

  if (!resetToken || typeof password !== "string" || password.length < 6) {
    return res.status(400).json({
      success: false,
      message: "Reset token and a password with at least 6 characters are required.",
    });
  }

  try {
    const decoded = jwt.verify(resetToken, getJwtSecret());

    if (!decoded.email || decoded.purpose !== "password_reset") {
      return res.status(400).json({
        success: false,
        message: "Invalid reset token.",
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const result = await pool.query(
      `UPDATE users
       SET password_hash = $1, updated_at = NOW()
       WHERE email = $2
       RETURNING id`,
      [passwordHash, decoded.email]
    );

    if (!result.rowCount) {
      return res.status(404).json({
        success: false,
        message: "User not found.",
      });
    }

    return res.json({
      success: true,
      message: "Password reset successful.",
    });
  } catch (error) {
    console.error("Reset password error:", error.message);

    return res.status(400).json({
      success: false,
      message: "Invalid or expired reset token.",
    });
  }
});

module.exports = router;
