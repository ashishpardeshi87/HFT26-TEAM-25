import { api, getSessionCredentials } from "./api.js";

const URL_SCHEME = /^[a-z][a-z\d+.-]*:/i;
const CONTROL_CHARACTER = /[\u0000-\u001f\u007f]/;

function assertSafeDarkguardPath(path) {
  if (typeof path !== "string") throw new TypeError("DarkGuard API path must be a string.");
  if (URL_SCHEME.test(path) || path.startsWith("//")) {
    throw new Error("Absolute DarkGuard API URLs are not allowed.");
  }
  if (!path.startsWith("/")) throw new Error("DarkGuard API path must start with '/'.");
  if (path.includes("\\") || CONTROL_CHARACTER.test(path)) {
    throw new Error("Invalid DarkGuard API path.");
  }

  let decoded = path;
  for (let pass = 0; pass < 6; pass += 1) {
    if (URL_SCHEME.test(decoded) || decoded.startsWith("//") || decoded.includes("\\")) {
      throw new Error("Invalid DarkGuard API path.");
    }

    const pathname = decoded.split(/[?#]/, 1)[0];
    if (pathname.split("/").some((segment) => segment === "." || segment === "..")) {
      throw new Error("DarkGuard API path traversal is not allowed.");
    }

    let next;
    try {
      next = decodeURIComponent(decoded);
    } catch {
      if (pass === 0) throw new Error("DarkGuard API path contains invalid encoding.");
      break;
    }
    if (next === decoded) break;
    decoded = next;
  }

  return path;
}

function sentinelHeaders() {
  const session = getSessionCredentials();
  return {
    ...(session?.session_id ? { "X-Sentinel-Session": session.session_id } : {}),
    ...(session?.gateway_token ? { "X-Sentinel-Token": session.gateway_token } : {}),
  };
}

function safeFilename(filename) {
  const cleaned = String(filename || "darkguard-download")
    .replace(/[\u0000-\u001f\u007f\\/:*?"<>|]/g, "_")
    .replace(/^\.+/, "")
    .slice(0, 180);
  return cleaned || "darkguard-download";
}

async function downloadError(response) {
  const fallback = `Download failed (${response.status})`;
  const text = await response.text().catch(() => "");
  if (!text) return fallback;
  try {
    const data = JSON.parse(text);
    const detail = data?.detail;
    if (typeof detail === "string") return detail;
    if (Array.isArray(detail?.errors)) return detail.errors.join("; ");
    return detail?.detail || detail?.error || data?.error || fallback;
  } catch {
    return text.length <= 240 ? text : fallback;
  }
}

export function darkguardApi(path, options) {
  assertSafeDarkguardPath(path);
  return api("/darkguard/ui" + path, options);
}

export async function downloadDarkguardFile(path, filename) {
  assertSafeDarkguardPath(path);
  const response = await fetch("/api/darkguard/ui" + path, {
    method: "GET",
    headers: sentinelHeaders(),
  });
  if (!response.ok) throw new Error(await downloadError(response));

  const objectUrl = URL.createObjectURL(await response.blob());
  const anchor = document.createElement("a");
  try {
    anchor.href = objectUrl;
    anchor.download = safeFilename(filename);
    anchor.rel = "noopener";
    anchor.style.display = "none";
    document.body.appendChild(anchor);
    anchor.click();
  } finally {
    anchor.remove();
    window.setTimeout(() => URL.revokeObjectURL(objectUrl), 0);
  }
}
