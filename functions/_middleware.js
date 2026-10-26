
const SESSION_HOURS = 8;

function base64url(bytes) {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

async function sign(value, secret) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(value)
  );

  return base64url(new Uint8Array(signature));
}

async function validSession(token, secret) {
  if (!token || !secret) return false;

  const parts = token.split(".");
  if (parts.length !== 2) return false;

  const [issued, signature] = parts;
  if (!/^\d+$/.test(issued)) return false;

  const age = Date.now() / 1000 - Number(issued);
  if (age < 0 || age > SESSION_HOURS * 3600) return false;

  const expected = await sign(issued, secret);
  return signature === expected;
}

function loginPage(message = "") {
  return new Response(`<!doctype html>
<html lang="id">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Login Katalog Karyabilitas</title>
<style>
body{font-family:Arial,sans-serif;background:#f1f6f3;
display:grid;place-items:center;min-height:100vh;margin:0}
main{background:white;padding:28px;border-radius:14px;
width:min(340px,85%);box-shadow:0 4px 18px #0002}
h2{color:#2e7d32}
input,button{box-sizing:border-box;width:100%;padding:12px;
margin-top:12px;border-radius:7px}
input{border:1px solid #aaa}
button{background:#2e7d32;color:white;border:0;font-weight:bold}
p{color:#b00020}
</style>
</head>
<body><main>
<h2>Katalog Karyabilitas</h2>
<p>Masukkan password untuk membuka katalog.</p>
${message ? `<p>${message}</p>` : ""}
<form method="POST" action="/__login">
<input type="password" name="password" placeholder="Password"
required autocomplete="current-password">
<button type="submit">Buka Katalog</button>
</form>
</main></body></html>`, {
    status: 200,
    headers: { "Content-Type": "text/html; charset=UTF-8",
      "Cache-Control": "no-store" }
  });
}

export async function onRequest({ request, next, env }) {
  const url = new URL(request.url);
  const password = env.SITE_PASSWORD;
  const secret = env.SESSION_SECRET;

  if (!password || !secret) {
    return new Response("Pengaturan password Cloudflare belum lengkap.", {
      status: 503
    });
  }

  if (url.pathname === "/__login" && request.method === "POST") {
    const form = await request.formData();

    if (form.get("password") !== password) {
      return loginPage("Password salah. Coba lagi.");
    }

    const issued = Math.floor(Date.now() / 1000).toString();
    const token = issued + "." + await sign(issued, secret);

    return new Response(null, {
      status: 303,
      headers: {
        "Location": "/",
        "Set-Cookie": `catalog_auth=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${SESSION_HOURS * 3600}`,
        "Cache-Control": "no-store"
      }
    });
  }

  const cookies = request.headers.get("Cookie") || "";
  const match = cookies.match(/(?:^|;\s*)catalog_auth=([^;]+)/);

  if (await validSession(match?.[1], secret)) {
    return next();
  }

  return loginPage();
}
