#!/home/supasuge/.nvm/versions/node/v24.13.0/bin/node
const express = require("express");
const fs = require("node:fs");
const path = require("node:path");
const helmet = require("helmet");
const crypto = require("node:crypto");

const app = express();
const PORT = process.env.PORT || 3000;

const FLAG = fs.readFileSync(path.join(__dirname, "flag.txt"), "utf8").trim();
const DOCS_PATH = path.join(__dirname, "api-docs.html");
console.log(DOCS_PATH);
app.disable("x-powered-by");
app.set("trust proxy", false);

app.use(
  helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false,
  })
);

app.use(express.json({ limit: "16kb", strict: true }));

/*
 * Intentionally vulnerable deep merge.
 * Do not sanitize __proto__/constructor/prototype here;
 * that is the challenge primitive.
 */
function merge(target, source) {
  for (const key in source) {
    if (typeof source[key] === "object" && source[key] !== null) {
      if (typeof target[key] !== "object" || target[key] === null) {
        target[key] = {};
      }
      merge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

const users = {};

function rid(prefix) {
  return `${prefix}_${crypto.randomBytes(4).toString("hex")}`;
}

function nowIso() {
  return new Date().toISOString();
}

function pushActivity(user, action, extra = {}) {
  user.recentActivity.push({
    id: rid("evt"),
    action,
    ts: nowIso(),
    ...extra,
  });

  if (user.recentActivity.length > 50) {
    user.recentActivity = user.recentActivity.slice(-50);
  }
}

function buildDefaultUser(ip, userAgent = "unknown") {
  return {
    id: rid("usr"),
    username: "guest_" + Math.random().toString(36).slice(2, 8),
    email: null,
    bio: "Just a regular user.",
    theme: "dark",
    locale: "en-US",
    timezone: "UTC",
    marketingOptIn: false,

    preferences: {
      editorMode: "vim",
      dashboardLayout: "compact",
      telemetryLevel: "minimal",
      defaultLanding: "overview",
      itemsPerPage: 10,
    },

    notificationSettings: {
      email: false,
      push: false,
      securityAlerts: true,
      weeklyDigest: false,
    },

    profileStats: {
      loginCount: 1,
      reputation: 0,
      projectsViewed: 0,
      exportsGenerated: 0,
      notesCreated: 0,
    },

    dashboard: {
      widgets: [
        { id: rid("w"), type: "activity", enabled: true, position: 1 },
        { id: rid("w"), type: "notifications", enabled: true, position: 2 },
        { id: rid("w"), type: "apikeys", enabled: false, position: 3 },
      ],
    },

    notes: [
      {
        id: rid("note"),
        title: "Welcome",
        content: "Your profile workspace is ready.",
        createdAt: nowIso(),
        updatedAt: nowIso(),
        tags: ["system"],
      },
    ],

    apiKeys: [],

    sessions: [
      {
        id: rid("sess"),
        createdAt: nowIso(),
        ip,
        userAgent,
        current: true,
      },
    ],

    recentActivity: [],
  };
}

function getOrCreateUser(ip, userAgent) {
  if (!users[ip]) {
    users[ip] = buildDefaultUser(ip, userAgent);
    pushActivity(users[ip], "account_created");
  }
  return users[ip];
}

app.use((req, res, next) => {
  const ip = req.ip || "127.0.0.1";
  const userAgent = req.get("user-agent") || "unknown";
  const user = getOrCreateUser(ip, userAgent);

  req.session = { user };
  req.requestMeta = {
    ip,
    requestId: rid("req"),
    ts: nowIso(),
  };

  next();
});




app.get("/", (req, res) => {
  return res.redirect(302, "/docs");
});

app.post("/", (req, res) => {
  if (!req.is("application/json")) {
    return res.status(415).json({
      error: "Content-Type must be application/json"
    });
  }

  return res.json({
    message: "Welcome to Proto-Palooza!",
    version: "2.0.0",
    service: "profile-workspace-api",
    requestId: req.requestMeta.requestId,
    docs: "/docs",
    endpoints: {
      "GET  /": "Redirects to API docs",
      "POST /": "This help message (JSON)",
      "GET  /docs": "Interactive API docs",
      "GET  /health": "Service health check",
      "GET  /user": "View your profile",
      "POST /update": "Update your profile (JSON body)",
      "GET  /user/preferences": "View user preferences",
      "POST /user/preferences": "Update user preferences",
      "GET  /user/activity": "View recent user activity",
      "GET  /dashboard": "View dashboard configuration",
      "POST /dashboard/widgets": "Create a dashboard widget",
      "PATCH /dashboard/widgets/:id": "Update widget configuration",
      "GET  /notes": "List notes",
      "POST /notes": "Create a note",
      "PATCH /notes/:id": "Update a note",
      "DELETE /notes/:id": "Delete a note",
      "GET  /notifications": "View notification settings",
      "POST /notifications/test": "Queue a simulated test notification",
      "POST /apikeys": "Create a mock API key",
      "GET  /apikeys": "List API key metadata",
      "GET  /export": "Export account data",
      "GET  /admin": "Admin-only flag endpoint"
    }
  });
});


app.get("/docs", (req, res) => {
  return res.sendFile(DOCS_PATH);
});

app.get("/health", (req, res) => {
  return res.json({
    ok: true,
    uptimeSeconds: Math.floor(process.uptime()),
    service: "proto-palooza",
    version: "2.0.0",
    timestamp: nowIso(),
  });
});

/* ──────────────────────────────────────────────
 * User/profile routes
 * ────────────────────────────────────────────── */

app.get("/user", (req, res) => {
  return res.json({
    user: req.session.user,
    note: "Use POST /update with a JSON body to change your profile.",
  });
});

app.post("/update", (req, res) => {
  if (!req.body || typeof req.body !== "object" || Array.isArray(req.body)) {
    return res.status(400).json({ error: "Send a JSON object." });
  }

  merge(req.session.user, req.body);

  pushActivity(req.session.user, "profile_updated", {
    requestId: req.requestMeta.requestId,
  });

  return res.json({
    message: "Profile updated!",
    requestId: req.requestMeta.requestId,
    user: req.session.user,
  });
});

app.get("/user/preferences", (req, res) => {
  return res.json({
    preferences: req.session.user.preferences,
    editableKeys: [
      "editorMode",
      "dashboardLayout",
      "telemetryLevel",
      "defaultLanding",
      "itemsPerPage",
    ],
  });
});

app.post("/user/preferences", (req, res) => {
  if (!req.body || typeof req.body !== "object" || Array.isArray(req.body)) {
    return res.status(400).json({ error: "Send a JSON object." });
  }

  merge(req.session.user.preferences, req.body);

  pushActivity(req.session.user, "preferences_updated");

  return res.json({
    message: "Preferences updated!",
    preferences: req.session.user.preferences,
  });
});

app.get("/user/activity", (req, res) => {
  return res.json({
    userId: req.session.user.id,
    recentActivity: req.session.user.recentActivity.slice(-15).reverse(),
  });
});

/* ──────────────────────────────────────────────
 * Dashboard routes
 * ────────────────────────────────────────────── */

app.get("/dashboard", (req, res) => {
  return res.json({
    dashboard: req.session.user.dashboard,
  });
});

app.post("/dashboard/widgets", (req, res) => {
  const body = req.body || {};
  const type =
    typeof body.type === "string" && body.type.trim()
      ? body.type.trim().slice(0, 32)
      : "custom";
  const position =
    Number.isInteger(body.position) && body.position > 0 ? body.position : 99;

  const widget = {
    id: rid("w"),
    type,
    enabled: body.enabled !== false,
    position,
  };

  req.session.user.dashboard.widgets.push(widget);
  pushActivity(req.session.user, "dashboard_widget_created", {
    widgetId: widget.id,
    type,
  });

  return res.status(201).json({
    message: "Widget created.",
    widget,
  });
});

app.patch("/dashboard/widgets/:id", (req, res) => {
  const widget = req.session.user.dashboard.widgets.find(
    (w) => w.id === req.params.id
  );

  if (!widget) {
    return res.status(404).json({ error: "Widget not found." });
  }

  const body = req.body || {};

  if (typeof body.enabled === "boolean") {
    widget.enabled = body.enabled;
  }
  if (Number.isInteger(body.position) && body.position > 0) {
    widget.position = body.position;
  }
  if (typeof body.type === "string" && body.type.trim()) {
    widget.type = body.type.trim().slice(0, 32);
  }

  pushActivity(req.session.user, "dashboard_widget_updated", {
    widgetId: widget.id,
  });

  return res.json({
    message: "Widget updated.",
    widget,
  });
});

/* ──────────────────────────────────────────────
 * Notes routes
 * ────────────────────────────────────────────── */

app.get("/notes", (req, res) => {
  const tag =
    typeof req.query.tag === "string" && req.query.tag.trim()
      ? req.query.tag.trim()
      : null;

  const notes = tag
    ? req.session.user.notes.filter((n) => Array.isArray(n.tags) && n.tags.includes(tag))
    : req.session.user.notes;

  return res.json({
    total: notes.length,
    notes,
  });
});

app.post("/notes", (req, res) => {
  const body = req.body || {};

  const title =
    typeof body.title === "string" && body.title.trim()
      ? body.title.trim().slice(0, 80)
      : "Untitled";

  const content =
    typeof body.content === "string" ? body.content.slice(0, 4000) : "";

  const tags = Array.isArray(body.tags)
    ? body.tags
        .filter((t) => typeof t === "string" && t.trim())
        .map((t) => t.trim().slice(0, 24))
        .slice(0, 8)
    : [];

  const note = {
    id: rid("note"),
    title,
    content,
    tags,
    createdAt: nowIso(),
    updatedAt: nowIso(),
  };

  req.session.user.notes.push(note);
  req.session.user.profileStats.notesCreated += 1;

  pushActivity(req.session.user, "note_created", {
    noteId: note.id,
  });

  return res.status(201).json({
    message: "Note created.",
    note,
  });
});

app.patch("/notes/:id", (req, res) => {
  const note = req.session.user.notes.find((n) => n.id === req.params.id);

  if (!note) {
    return res.status(404).json({ error: "Note not found." });
  }

  const body = req.body || {};

  if (typeof body.title === "string" && body.title.trim()) {
    note.title = body.title.trim().slice(0, 80);
  }
  if (typeof body.content === "string") {
    note.content = body.content.slice(0, 4000);
  }
  if (Array.isArray(body.tags)) {
    note.tags = body.tags
      .filter((t) => typeof t === "string" && t.trim())
      .map((t) => t.trim().slice(0, 24))
      .slice(0, 8);
  }

  note.updatedAt = nowIso();

  pushActivity(req.session.user, "note_updated", {
    noteId: note.id,
  });

  return res.json({
    message: "Note updated.",
    note,
  });
});

app.delete("/notes/:id", (req, res) => {
  const idx = req.session.user.notes.findIndex((n) => n.id === req.params.id);

  if (idx === -1) {
    return res.status(404).json({ error: "Note not found." });
  }

  const [deleted] = req.session.user.notes.splice(idx, 1);

  pushActivity(req.session.user, "note_deleted", {
    noteId: deleted.id,
  });

  return res.json({
    message: "Note deleted.",
    noteId: deleted.id,
  });
});

/* ──────────────────────────────────────────────
 * Notification + API key routes
 * ────────────────────────────────────────────── */

app.get("/notifications", (req, res) => {
  return res.json({
    notificationSettings: req.session.user.notificationSettings,
  });
});

app.post("/notifications/test", (req, res) => {
  const channel =
    req.body && typeof req.body.channel === "string"
      ? req.body.channel.trim().slice(0, 24)
      : "security";

  pushActivity(req.session.user, "test_notification_queued", {
    channel,
  });

  return res.json({
    queued: true,
    channel,
    etaSeconds: 3,
  });
});

app.get("/apikeys", (req, res) => {
  return res.json({
    total: req.session.user.apiKeys.length,
    apiKeys: req.session.user.apiKeys,
  });
});

app.post("/apikeys", (req, res) => {
  const label =
    req.body && typeof req.body.label === "string" && req.body.label.trim()
      ? req.body.label.trim().slice(0, 32)
      : "default";

  const fakeKey =
    "ppz_" +
    crypto.randomBytes(8).toString("hex") +
    crypto.randomBytes(8).toString("hex");

  const record = {
    id: rid("key"),
    label,
    prefix: fakeKey.slice(0, 12),
    createdAt: nowIso(),
    lastUsedAt: null,
  };

  req.session.user.apiKeys.push(record);

  pushActivity(req.session.user, "api_key_created", {
    keyId: record.id,
    label,
  });

  return res.status(201).json({
    message: "API key created.",
    apiKey: fakeKey,
    metadata: record,
  });
});

/* ──────────────────────────────────────────────
 * Export route
 * ────────────────────────────────────────────── */

app.get("/export", (req, res) => {
  req.session.user.profileStats.exportsGenerated += 1;
  pushActivity(req.session.user, "account_export_generated");

  return res.json({
    exportedAt: nowIso(),
    user: req.session.user,
  });
});

/* ──────────────────────────────────────────────
 * Admin route
 * ────────────────────────────────────────────── */

app.get("/admin", (req, res) => {
  if (req.session.user.isAdmin) {
    return res.json({
      message: "Welcome, admin!",
      flag: FLAG,
      audit: {
        requestId: req.requestMeta.requestId,
        ts: req.requestMeta.ts,
      },
    });
  }

  return res.status(403).json({
    error: "Access denied. Admins only.",
    requestId: req.requestMeta.requestId,
  });
});

/* ──────────────────────────────────────────────
 * 404
 * ────────────────────────────────────────────── */

app.use((req, res) => {
  return res.status(404).json({
    error: "Not found",
    path: req.path,
    requestId: req.requestMeta ? req.requestMeta.requestId : null,
  });
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`[Proto-Palooza] Listening on port ${PORT}`);
});