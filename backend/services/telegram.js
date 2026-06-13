// services/telegram.js
const axios = require("axios");
const db = require("../db");
const moment = require("moment");

/* -------------------------------------------------------------------------- */
/* ADMIN CHAT IDS (optional restriction)                                      */
/* -------------------------------------------------------------------------- */
// TELEGRAM_ADMIN_CHAT_IDS=123456789,987654321
const TELEGRAM_ADMIN_CHAT_IDS = (process.env.TELEGRAM_ADMIN_CHAT_IDS || "")
  .split(",")
  .map(id => id.trim())
  .filter(Boolean);

function isAllowedChat(chatId) {
  if (!TELEGRAM_ADMIN_CHAT_IDS.length) return true; // allow all if not set
  return TELEGRAM_ADMIN_CHAT_IDS.includes(String(chatId));
}

/* -------------------------------------------------------------------------- */
/* BUILD LATEST TICKETS MESSAGE (no bot here, just returns text)             */
/* -------------------------------------------------------------------------- */
async function buildLatestTicketsMessage() {
  const [rows] = await db
    .promise()
    .query(
      "SELECT id, user_id, subject, status, created_at FROM support_tickets ORDER BY created_at DESC LIMIT 10"
    );

  if (!rows.length) {
    return "📭 No support tickets found.";
  }

  let msg = "<b>🎫 Latest Support Tickets</b>\n\n";
  rows.forEach(t => {
    msg += `🆔 <b>ID:</b> ${t.id}\n`;
    msg += `👤 <b>User ID:</b> ${t.user_id}\n`;
    msg += `📌 <b>Subject:</b> ${t.subject}\n`;
    msg += `📍 <b>Status:</b> ${t.status}\n`;
    msg += `⏱️ <b>${moment(t.created_at).format("YYYY-MM-DD HH:mm:ss")}</b>\n\n`;
  });

  return msg;
}

/* -------------------------------------------------------------------------- */
/* NOTIFY ADMINS – now supports inline buttons                               */
/* -------------------------------------------------------------------------- */
/**
 * notifyAdmins(message, replyMarkup?)
 *
 * message: string (HTML)
 * replyMarkup: optional Telegram reply_markup object:
 *   { inline_keyboard: [ [ { text, callback_data }, ... ] ] }
 */
async function notifyAdmins(message, replyMarkup) {
  try {
    const token = process.env.TELEGRAM_BOT_TOKEN;
    const ids = (process.env.TELEGRAM_ADMIN_CHAT_IDS || "")
      .split(",")
      .map(id => id.trim())
      .filter(Boolean);

    if (!token || !ids.length) {
      console.warn("Telegram not configured properly");
      return;
    }

    const baseUrl = `https://api.telegram.org/bot${token}/sendMessage`;

    await Promise.all(
      ids.map(chatId =>
        axios
          .post(baseUrl, {
            chat_id: chatId,
            text: message,
            parse_mode: "HTML",
            ...(replyMarkup ? { reply_markup: replyMarkup } : {})
          })
          .catch(err => {
            console.error(
              "Telegram send error:",
              err.response?.data || err.message
            );
          })
      )
    );
  } catch (e) {
    console.error("notifyAdmins error:", e.message);
  }
}

module.exports = {
  isAllowedChat,
  buildLatestTicketsMessage,
  notifyAdmins,
};
