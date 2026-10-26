
const SESSION_HOURS = 8;
const CATALOG = "/katalog-karyabilitas.html";

function base64url(bytes) {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function sign(value, secret) {
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const sig = await crypto.subtle.sign(
    "HMAC", key, new TextEncoder().encode(value)
  );
  return base64url(new Uint8Array(sig));
}

async function validSession(token, secret) {
  if (!token || !secret) return false;
  const parts = token.split(".");
  if (parts.length !== 2 || !/^\d+$/.test(parts[0])) return false;
  const age = Date.now() / 1000 - Number(parts[0]);
  return age >= 0 && age <= SESSION_HOURS * 3600 &&
    parts[1] === await sign(parts[0], secret);
}

function loginPage(message = "") {
  return new Response(`<!doctype html>
<html lang="id"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Login Katalog Karyabilitas</title>
<body style="font-family:Arial;background:#f1f6f3;text-align:center;padding:50px">
<h2>Katalog Karyabilitas</h2><p>Masukkan password untuk membuka katalog.</p>
<p style="color:#b00020">${message}</p>
<form method="POST" action="/__login">
<input type="password" name="password" placeholder="Password" required>
<button type="submit">Buka Katalog</button>
</form></body></html>`, {
    headers: {
      "Content-Type": "text/html; charset=UTF-8",
      "Cache-Control": "no-store"
    }
  });
}

export async function onRequest({ request, next, env }) {
  const url = new URL(request.url);

  if (url.pathname !== CATALOG && url.pathname !== "/__login") {
    return next();
  }

  const password = env.SITE_PASSWORD;
  const secret = env.SESSION_SECRET;

  if (!password || !secret) {
    return new Response("Pengaturan password Cloudflare belum lengkap.", { status: 503 });
  }

  if (url.pathname === "/__login" && request.method === "POST") {
    const form = await request.formData();
    if (form.get("password") !== password) return loginPage("Password salah.");

    const issued = Math.floor(Date.now() / 1000).toString();
    const token = issued + "." + await sign(issued, secret);

    return new Response(null, {
      status: 303,
      headers: {
        "Location": CATALOG,
        "Set-Cookie": `catalog_auth=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${SESSION_HOURS * 3600}`,
        "Cache-Control": "no-store"
      }
    });
  }

  const match = (request.headers.get("Cookie") || "")
    .match(/(?:^|;\s*)catalog_auth=([^;]+)/);

  if (await validSession(match?.[1], secret)) return next();
  return loginPage();
}
