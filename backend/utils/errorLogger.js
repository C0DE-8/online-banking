const fs = require("fs");
const path = require("path");

const LOG_DIR = path.join(__dirname, "..", "logs");
const ERROR_LOG_FILE = path.join(LOG_DIR, "error.log");

const SENSITIVE_KEYS = new Set([
  "password",
  "new_password",
  "old_password",
  "confirm_password",
  "token",
  "authorization",
  "pin",
  "otp",
  "imf_code",
  "cot_code",
  "tax_code",
]);

function ensureLogDir() {
  fs.mkdirSync(LOG_DIR, { recursive: true });
}

function redact(value) {
  if (Array.isArray(value)) return value.map(redact);
  if (!value || typeof value !== "object") return value;

  return Object.fromEntries(
    Object.entries(value).map(([key, item]) => [
      key,
      SENSITIVE_KEYS.has(String(key).toLowerCase()) ? "[REDACTED]" : redact(item),
    ])
  );
}

function serializeError(err) {
  if (!err) return null;
  return {
    name: err.name,
    message: err.message || String(err),
    stack: err.stack,
    code: err.code,
    errno: err.errno,
    sqlMessage: err.sqlMessage,
    sqlState: err.sqlState,
  };
}

function appendErrorLog(entry) {
  try {
    ensureLogDir();
    fs.appendFileSync(ERROR_LOG_FILE, `${JSON.stringify(entry)}\n`);
  } catch (err) {
    console.error("Failed to write API error log:", err.message);
  }
}

function buildRequestLog(req, extra = {}) {
  return {
    timestamp: new Date().toISOString(),
    method: req.method,
    url: req.originalUrl || req.url,
    ip: req.ip,
    user_id: req.user?.id || null,
    status_code: extra.statusCode || null,
    request_body: redact(req.body || {}),
    response_body: redact(extra.responseBody || null),
    error: serializeError(extra.error),
  };
}

function requestFailureLogger(req, res, next) {
  let responseBody = null;

  const originalJson = res.json.bind(res);
  res.json = (body) => {
    responseBody = body;
    return originalJson(body);
  };

  const originalSend = res.send.bind(res);
  res.send = (body) => {
    if (responseBody === null) responseBody = body;
    return originalSend(body);
  };

  res.on("finish", () => {
    if (res.statusCode >= 400 && !res.locals.errorLogged) {
      appendErrorLog(buildRequestLog(req, {
        statusCode: res.statusCode,
        responseBody,
      }));
    }
  });

  next();
}

function expressErrorLogger(err, req, res, next) {
  res.locals.errorLogged = true;

  appendErrorLog(buildRequestLog(req, {
    statusCode: err.status || err.statusCode || 500,
    error: err,
  }));

  if (res.headersSent) return next(err);

  const status = err.status || err.statusCode || 500;
  res.status(status).json({
    error: status >= 500 ? "Internal server error" : err.message,
  });
}

module.exports = {
  ERROR_LOG_FILE,
  appendErrorLog,
  requestFailureLogger,
  expressErrorLogger,
};
