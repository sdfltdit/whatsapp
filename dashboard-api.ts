import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import bcrypt from "https://esm.sh/bcryptjs@2.4.3";

// ═══════════════════════════════════════════════════════════════════════════
// DASHBOARD-API — secure backend proxy for the SDF Inbox dashboard.
//
// WHY THIS EXISTS: the previous dashboard.html called Supabase directly from
// the browser using the SUPABASE SERVICE_ROLE KEY (full, unrestricted DB
// access — bypasses Row Level Security entirely) and called the WhatsApp
// Graph API directly using a live WA_ACCESS_TOKEN. Both were hardcoded in
// plaintext in a PUBLIC GitHub repo. Anyone who opened DevTools (F12), or
// anyone who ever viewed that repo, could copy these credentials and get
// full read/write/delete access to every customer conversation, or send
// messages as SDF Clothing's WhatsApp number, or download staff password
// hashes from `staff_users`.
//
// This function fixes that: all secrets (SUPABASE_SERVICE_ROLE_KEY,
// WA_ACCESS_TOKEN, SESSION_SECRET) live ONLY here, as server-side env
// secrets, and are never sent to the browser. The dashboard now only ever
// holds a short-lived, signed session token — which is useless without this
// server's SESSION_SECRET to forge, and expires on its own.
//
// Required Supabase secrets (set via: supabase secrets set NAME=value):
//   SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY  (same values as whatsapp-webhook)
//   WA_ACCESS_TOKEN, WA_PHONE_NUMBER_ID       (same values as whatsapp-webhook)
//   SESSION_SECRET                            (new — any long random string)
//   ALLOWED_ORIGIN                            (e.g. https://inbox.sdfltd.com)
// ═══════════════════════════════════════════════════════════════════════════

const SUPABASE_URL         = Deno.env.get("SUPABASE_URL")!;
const SUPABASE_SERVICE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const WA_ACCESS_TOKEN      = Deno.env.get("WA_ACCESS_TOKEN")!;
const WA_PHONE_NUMBER_ID   = Deno.env.get("WA_PHONE_NUMBER_ID")!;
const SESSION_SECRET       = Deno.env.get("SESSION_SECRET")!;
const ALLOWED_ORIGIN       = Deno.env.get("ALLOWED_ORIGIN") || "*";
const SESSION_TTL_MS       = 8 * 60 * 60 * 1000; // 8 hours

const sb = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY);

// ───────────────────────── CORS ─────────────────────────
const CORS_HEADERS = {
  "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
  "Access-Control-Allow-Methods": "GET, POST, PATCH, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
};

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json", ...CORS_HEADERS } });
}

// ───────────────────────── Signed session tokens (HMAC-SHA256, no JWT lib needed) ─────────────────────────
function b64url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64urlDecode(s: string): string {
  const padded = s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4);
  return atob(padded);
}
async function hmac(data: string): Promise<string> {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(SESSION_SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
  return b64url(new Uint8Array(sig));
}
async function createSessionToken(payload: Record<string, unknown>): Promise<string> {
  const body = b64url(new TextEncoder().encode(JSON.stringify({ ...payload, exp: Date.now() + SESSION_TTL_MS })));
  const sig = await hmac(body);
  return `${body}.${sig}`;
}
async function verifySessionToken(token: string): Promise<Record<string, unknown> | null> {
  const [body, sig] = (token || "").split(".");
  if (!body || !sig) return null;
  const expected = await hmac(body);
  // constant-time-ish comparison
  if (expected.length !== sig.length) return null;
  let diff = 0;
  for (let i = 0; i < expected.length; i++) diff |= expected.charCodeAt(i) ^ sig.charCodeAt(i);
  if (diff !== 0) return null;
  try {
    const payload = JSON.parse(b64urlDecode(body));
    if (!payload.exp || Date.now() > payload.exp) return null;
    return payload;
  } catch {
    return null;
  }
}

async function requireAuth(req: Request): Promise<{ email: string; role: string; full_name: string } | null> {
  const authHeader = req.headers.get("Authorization") || "";
  const token = authHeader.replace(/^Bearer\s+/i, "");
  const payload = await verifySessionToken(token);
  if (!payload) return null;
  return payload as { email: string; role: string; full_name: string };
}

// ───────────────────────── Login (bcrypt only — no fallback/backdoor) ─────────────────────────
async function handleLogin(req: Request): Promise<Response> {
  let body: { email?: string; password?: string };
  try { body = await req.json(); } catch { return json({ error: "Invalid request body" }, 400); }
  const email = (body.email || "").trim().toLowerCase();
  const password = body.password || "";
  if (!email || !password) return json({ error: "Email and password are required" }, 400);

  const { data: user, error } = await sb
    .from("staff_users")
    .select("id, email, full_name, role, password_hash, status")
    .eq("email", email)
    .eq("status", "active")
    .maybeSingle();

  if (error || !user || !user.password_hash) {
    // Same generic message whether the user doesn't exist or the password is wrong —
    // don't reveal which, so an attacker can't enumerate valid staff emails.
    return json({ error: "Incorrect email or password." }, 401);
  }

  const valid = bcrypt.compareSync(password, user.password_hash);
  if (!valid) return json({ error: "Incorrect email or password." }, 401);

  const token = await createSessionToken({ email: user.email, role: user.role, full_name: user.full_name });
  return json({ token, user: { email: user.email, full_name: user.full_name, role: user.role } });
}

// ───────────────────────── Conversations ─────────────────────────
async function handleGetConversations(): Promise<Response> {
  const { data, error } = await sb
    .from("wa_conversations")
    .select("*")
    .order("last_message_at", { ascending: false, nullsFirst: false })
    .order("created_at", { ascending: false })
    .limit(100);
  if (error) return json({ error: error.message }, 500);
  return json(data || []);
}

async function handleConversationStatus(req: Request): Promise<Response> {
  let body: { conversation_id?: string; status?: string };
  try { body = await req.json(); } catch { return json({ error: "Invalid request body" }, 400); }
  const { conversation_id, status } = body;
  const ALLOWED = ["open", "bot", "escalated", "missed", "resolved", "blocked"];
  if (!conversation_id || !status || !ALLOWED.includes(status)) return json({ error: "Invalid conversation_id or status" }, 400);
  const { error } = await sb.from("wa_conversations").update({ status }).eq("id", conversation_id);
  if (error) return json({ error: error.message }, 500);
  return json({ ok: true });
}

async function handleMuteConversation(req: Request): Promise<Response> {
  let body: { conversation_id?: string; muted?: boolean };
  try { body = await req.json(); } catch { return json({ error: "Invalid request body" }, 400); }
  if (!body.conversation_id) return json({ error: "conversation_id is required" }, 400);
  const { error } = await sb.from("wa_conversations").update({ muted: !!body.muted }).eq("id", body.conversation_id);
  if (error) return json({ error: error.message }, 500);
  return json({ ok: true });
}

// ───────────────────────── Messages ─────────────────────────
async function handleGetMessages(url: URL): Promise<Response> {
  const conversationId = url.searchParams.get("conversation_id");
  if (!conversationId) return json({ error: "conversation_id is required" }, 400);
  const { data, error } = await sb
    .from("wa_messages")
    .select("*")
    .eq("conversation_id", conversationId)
    .order("sent_at", { ascending: true })
    .limit(300);
  if (error) return json({ error: error.message }, 500);
  return json(data || []);
}

async function handleSystemMessage(req: Request): Promise<Response> {
  let body: { conversation_id?: string; text?: string };
  try { body = await req.json(); } catch { return json({ error: "Invalid request body" }, 400); }
  if (!body.conversation_id || !body.text) return json({ error: "conversation_id and text are required" }, 400);
  const { error } = await sb.from("wa_messages").insert({
    conversation_id: body.conversation_id, direction: "outbound", content: body.text,
    message_type: "system", sender_type: "system", status: "sent", sent_at: new Date().toISOString(),
  });
  if (error) return json({ error: error.message }, 500);
  return json({ ok: true });
}

async function handleDeleteMessage(req: Request): Promise<Response> {
  let body: { message_id?: string };
  try { body = await req.json(); } catch { return json({ error: "Invalid request body" }, 400); }
  if (!body.message_id) return json({ error: "message_id is required" }, 400);
  const { error } = await sb.from("wa_messages").update({ is_deleted: true }).eq("id", body.message_id);
  if (error) return json({ error: error.message }, 500);
  return json({ ok: true });
}

async function handleMarkRead(req: Request): Promise<Response> {
  let body: { conversation_id?: string };
  try { body = await req.json(); } catch { return json({ error: "Invalid request body" }, 400); }
  if (!body.conversation_id) return json({ error: "conversation_id is required" }, 400);
  const { data: unread } = await sb
    .from("wa_messages")
    .select("id, wa_message_id")
    .eq("conversation_id", body.conversation_id)
    .eq("direction", "inbound")
    .eq("status", "received")
    .not("wa_message_id", "is", null);
  for (const m of unread || []) {
    try {
      await fetch(`https://graph.facebook.com/v19.0/${WA_PHONE_NUMBER_ID}/messages`, {
        method: "POST",
        headers: { Authorization: `Bearer ${WA_ACCESS_TOKEN}`, "Content-Type": "application/json" },
        body: JSON.stringify({ messaging_product: "whatsapp", status: "read", message_id: m.wa_message_id }),
      });
    } catch { /* best-effort */ }
  }
  return json({ ok: true });
}

// ───────────────────────── Send text reply (agent) ─────────────────────────
async function handleSendText(req: Request, agent: { email: string }): Promise<Response> {
  let body: { conversation_id?: string; text?: string; reply_to?: { id: string; wa_message_id?: string; content?: string; sender_label?: string } };
  try { body = await req.json(); } catch { return json({ error: "Invalid request body" }, 400); }
  const { conversation_id, text, reply_to } = body;
  if (!conversation_id || !text) return json({ error: "conversation_id and text are required" }, 400);

  const { data: conv } = await sb.from("wa_conversations").select("phone_number").eq("id", conversation_id).maybeSingle();
  if (!conv?.phone_number) return json({ error: "Conversation has no phone number" }, 404);

  const payload: Record<string, unknown> = { messaging_product: "whatsapp", to: conv.phone_number, type: "text", text: { body: text } };
  if (reply_to?.wa_message_id) payload.context = { message_id: reply_to.wa_message_id };

  const waRes = await fetch(`https://graph.facebook.com/v19.0/${WA_PHONE_NUMBER_ID}/messages`, {
    method: "POST",
    headers: { Authorization: `Bearer ${WA_ACCESS_TOKEN}`, "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!waRes.ok) {
    const err = await waRes.json().catch(() => ({}));
    return json({ error: err?.error?.message || "WhatsApp send failed" }, 502);
  }
  const result = await waRes.json();
  const waMsgId = result?.messages?.[0]?.id || null;

  const row: Record<string, unknown> = {
    conversation_id, direction: "outbound", content: text, message_type: "text",
    wa_message_id: waMsgId, status: "sent", sender_type: "agent", sent_at: new Date().toISOString(),
  };
  if (reply_to) { row.reply_to_id = reply_to.id; row.reply_preview = reply_to.content; row.reply_sender = reply_to.sender_label; }

  await sb.from("wa_messages").insert(row);
  await sb.from("wa_conversations").update({ last_message: text, last_message_at: new Date().toISOString() }).eq("id", conversation_id);

  return json({ ok: true });
}

// ───────────────────────── Send media reply (agent uploads image/video/document) ─────────────────────────
async function handleSendMedia(req: Request): Promise<Response> {
  const formData = await req.formData();
  const file = formData.get("file") as File | null;
  const conversationId = formData.get("conversation_id") as string | null;
  const kind = (formData.get("kind") as string | null) || "document";
  const caption = (formData.get("caption") as string | null) || "";
  if (!file || !conversationId) return json({ error: "file and conversation_id are required" }, 400);

  const { data: conv } = await sb.from("wa_conversations").select("phone_number").eq("id", conversationId).maybeSingle();
  if (!conv?.phone_number) return json({ error: "Conversation has no phone number" }, 404);

  const uploadForm = new FormData();
  uploadForm.append("file", file);
  uploadForm.append("messaging_product", "whatsapp");
  uploadForm.append("type", file.type);

  const uploadRes = await fetch(`https://graph.facebook.com/v19.0/${WA_PHONE_NUMBER_ID}/media`, {
    method: "POST",
    headers: { Authorization: `Bearer ${WA_ACCESS_TOKEN}` },
    body: uploadForm,
  });
  if (!uploadRes.ok) return json({ error: "Media upload to WhatsApp failed" }, 502);
  const { id: mediaId } = await uploadRes.json();

  const msgBody: Record<string, unknown> = { messaging_product: "whatsapp", to: conv.phone_number, type: kind };
  msgBody[kind] = kind === "document"
    ? { id: mediaId, filename: file.name, ...(caption ? { caption } : {}) }
    : { id: mediaId, ...(caption ? { caption } : {}) };

  const waRes = await fetch(`https://graph.facebook.com/v19.0/${WA_PHONE_NUMBER_ID}/messages`, {
    method: "POST",
    headers: { Authorization: `Bearer ${WA_ACCESS_TOKEN}`, "Content-Type": "application/json" },
    body: JSON.stringify(msgBody),
  });
  if (!waRes.ok) return json({ error: "WhatsApp send failed" }, 502);
  const result = await waRes.json();

  await sb.from("wa_messages").insert({
    conversation_id: conversationId, direction: "outbound", content: caption || file.name, message_type: kind,
    wa_message_id: result?.messages?.[0]?.id || null, status: "sent", sender_type: "agent", sent_at: new Date().toISOString(),
  });
  await sb.from("wa_conversations").update({ last_message: `[${kind}] ${caption || file.name}`, last_message_at: new Date().toISOString() }).eq("id", conversationId);

  return json({ ok: true });
}

// ───────────────────────── Forward a message to another conversation ─────────────────────────
async function handleForward(req: Request): Promise<Response> {
  let body: { message_id?: string; target_conversation_id?: string };
  try { body = await req.json(); } catch { return json({ error: "Invalid request body" }, 400); }
  const { message_id, target_conversation_id } = body;
  if (!message_id || !target_conversation_id) return json({ error: "message_id and target_conversation_id are required" }, 400);

  const { data: msg } = await sb.from("wa_messages").select("*").eq("id", message_id).maybeSingle();
  const { data: target } = await sb.from("wa_conversations").select("phone_number").eq("id", target_conversation_id).maybeSingle();
  if (!msg || !target?.phone_number) return json({ error: "Message or target conversation not found" }, 404);

  let waRes: Response;
  if (msg.message_type === "text" || !msg.media_url) {
    waRes = await fetch(`https://graph.facebook.com/v19.0/${WA_PHONE_NUMBER_ID}/messages`, {
      method: "POST",
      headers: { Authorization: `Bearer ${WA_ACCESS_TOKEN}`, "Content-Type": "application/json" },
      body: JSON.stringify({ messaging_product: "whatsapp", to: target.phone_number, type: "text", text: { body: msg.content || "" } }),
    });
  } else {
    const waBody: Record<string, unknown> = { messaging_product: "whatsapp", to: target.phone_number, type: msg.message_type };
    waBody[msg.message_type] = { link: msg.media_url };
    waRes = await fetch(`https://graph.facebook.com/v19.0/${WA_PHONE_NUMBER_ID}/messages`, {
      method: "POST",
      headers: { Authorization: `Bearer ${WA_ACCESS_TOKEN}`, "Content-Type": "application/json" },
      body: JSON.stringify(waBody),
    });
  }
  if (!waRes.ok) return json({ error: "Forward failed" }, 502);
  const result = await waRes.json();

  await sb.from("wa_messages").insert({
    conversation_id: target_conversation_id, direction: "outbound", content: msg.content || "", message_type: msg.message_type,
    media_url: msg.media_url || null, wa_message_id: result?.messages?.[0]?.id || null, status: "sent",
    sender_type: "agent", is_forwarded: true, sent_at: new Date().toISOString(),
  });

  return json({ ok: true });
}

// ───────────────────────── Router ─────────────────────────
serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS_HEADERS });

  const url = new URL(req.url);
  // Works regardless of whether Supabase serves this at /dashboard-api/... or /functions/v1/dashboard-api/...
  const path = url.pathname.replace(/^.*\/dashboard-api/, "") || "/";

  try {
    if (path === "/login" && req.method === "POST") return await handleLogin(req);

    // Every route below requires a valid session
    const agent = await requireAuth(req);
    if (!agent) return json({ error: "Unauthorized — please log in again." }, 401);

    if (path === "/conversations" && req.method === "GET") return await handleGetConversations();
    if (path === "/conversation-status" && req.method === "PATCH") return await handleConversationStatus(req);
    if (path === "/conversation-mute" && req.method === "PATCH") return await handleMuteConversation(req);
    if (path === "/messages" && req.method === "GET") return await handleGetMessages(url);
    if (path === "/system-message" && req.method === "POST") return await handleSystemMessage(req);
    if (path === "/message-delete" && req.method === "PATCH") return await handleDeleteMessage(req);
    if (path === "/mark-read" && req.method === "POST") return await handleMarkRead(req);
    if (path === "/send-text" && req.method === "POST") return await handleSendText(req, agent);
    if (path === "/send-media" && req.method === "POST") return await handleSendMedia(req);
    if (path === "/forward" && req.method === "POST") return await handleForward(req);

    return json({ error: "Not found" }, 404);
  } catch (e) {
    console.error("dashboard-api error:", e);
    return json({ error: "Internal server error" }, 500);
  }
});
