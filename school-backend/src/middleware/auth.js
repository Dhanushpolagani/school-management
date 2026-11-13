
const jwt = require("jsonwebtoken");

const ROLES = [
  "super_admin",
  "school_admin",
  "admin",
  "accountant",
  "hr_manager",
  "teacher",
  "librarian",
  "hostel_warden",
  "transport_manager",
  "parent",
  "student",
];

function verifyToken(req, res, next) {
  const secret = process.env.JWT_SECRET;

  if (!secret || secret.length < 32) {
    console.error("JWT_SECRET is missing or too short.");
    return res.status(500).json({
      success: false,
      message: "Authentication configuration error.",
    });
  }

  let token = req.cookies?.access_token;

  if (!token && req.headers.authorization?.startsWith("Bearer ")) {
    token = req.headers.authorization.substring(7).trim();
  }

  if (!token) {
    return res.status(401).json({
      success: false,
      message: "Authentication required.",
    });
  }

  try {
    const decoded = jwt.verify(token, secret);

    const userId = decoded.sub || decoded.id;
    const tenantId = decoded.tenantId || decoded.tenant_id;
    const roles = Array.isArray(decoded.roles)
      ? decoded.roles
      : [decoded.role || "student"];

    if (
      !userId ||
      !tenantId ||
      decoded.tokenType !== "access"
    ) {
      return res.status(401).json({
        success: false,
        message: "Invalid authentication token.",
      });
    }

    req.user = {
      ...decoded,
      id: String(userId),
      sub: String(userId),
      tenantId: String(tenantId),
      role: roles[0],
      roles,
    };

    req.tenantId = String(tenantId);

    return next();
  } catch (error) {
    return res.status(401).json({
      success: false,
      message: "Token expired or invalid.",
    });
  }
}

function requireRole(...allowedRoles) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        message: "Authentication required.",
      });
    }

    const userRoles = req.user.roles || [req.user.role];

    const hasRole = userRoles.some((role) =>
      allowedRoles.includes(role) ||
      (role === "school_admin" && allowedRoles.includes("admin")) ||
      (role === "admin" && allowedRoles.includes("school_admin"))
    );

    if (!hasRole) {
      return res.status(403).json({
        success: false,
        message: "Insufficient permissions.",
      });
    }

    return next();
  };
}

module.exports = {
  verifyToken,
  authenticateToken: verifyToken,
  requireRole,
  ROLES,
};
