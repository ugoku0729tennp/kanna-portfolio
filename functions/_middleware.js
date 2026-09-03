const COOKIE_NAME = "kanna_portfolio_auth";

async function makeToken(secret) {
  const data = new TextEncoder().encode("kanna-portfolio-auth");
  const keyData = new TextEncoder().encode(secret);

  const key = await crypto.subtle.importKey(
    "raw",
    keyData,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign("HMAC", key, data);

  return btoa(String.fromCharCode(...new Uint8Array(signature)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

async function isValidPassword(input, secret) {
  if (!secret) return false;

  const inputBytes = new TextEncoder().encode(input);
  const secretBytes = new TextEncoder().encode(secret);

  const inputHash = await crypto.subtle.digest("SHA-256", inputBytes);
  const secretHash = await crypto.subtle.digest("SHA-256", secretBytes);

  const a = new Uint8Array(inputHash);
  const b = new Uint8Array(secretHash);

  if (a.length !== b.length) return false;

  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a[i] ^ b[i];
  }

  return result === 0;
}

function getCookie(request, name) {
  const cookieHeader = request.headers.get("Cookie") || "";

  for (const cookie of cookieHeader.split(";")) {
    const [key, ...value] = cookie.trim().split("=");

    if (key === name) {
      return value.join("=");
    }
  }

  return null;
}

function loginPage(error = "") {
  return new Response(
    `<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>KANNA MAEDA</title>
<style>
* {
  box-sizing: border-box;
}

body {
  margin: 0;
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  background: #f5f4f0;
  color: #111;
  font-family: Arial, "Hiragino Kaku Gothic ProN", "Yu Gothic", sans-serif;
}

.container {
  width: min(420px, 88vw);
  text-align: center;
}

.eyebrow {
  font-size: 11px;
  letter-spacing: .25em;
  margin-bottom: 28px;
}

h1 {
  margin: 0;
  font-size: clamp(32px, 9vw, 52px);
  letter-spacing: .08em;
  font-weight: 500;
}

p {
  margin: 18px 0 32px;
  font-size: 13px;
  line-height: 1.8;
  color: #666;
}

form {
  display: flex;
  flex-direction: column;
  gap: 10px;
}

input {
  width: 100%;
  padding: 15px 16px;
  border: 1px solid #ccc;
  background: white;
  font-size: 16px;
  outline: none;
}

input:focus {
  border-color: #111;
}

button {
  width: 100%;
  padding: 15px;
  border: 0;
  background: #111;
  color: white;
  font-size: 13px;
  letter-spacing: .08em;
  cursor: pointer;
}

.error {
  margin: 0 0 14px;
  color: #b00020;
  font-size: 12px;
}
</style>
</head>

<body>
  <main class="container">
    <div class="eyebrow">KANNA MAEDA</div>
    <h1>PORTFOLIO</h1>
    <p>
      このサイトは限定公開です。<br>
      パスコードを入力してください。
    </p>

    ${error ? `<div class="error">${error}</div>` : ""}

    <form method="POST" action="/__login">
      <input
        type="password"
        name="password"
        placeholder="PASSCODE"
        autocomplete="current-password"
        required
        autofocus
      >
      <button type="submit">ENTER</button>
    </form>
  </main>
</body>
</html>`,
    {
      status: error ? 401 : 200,
      headers: {
        "Content-Type": "text/html; charset=UTF-8",
        "Cache-Control": "no-store"
      }
    }
  );
}

export async function onRequest(context) {
  const { request, env } = context;

  if (!env.SITE_PASSWORD) {
    return new Response(
      "SITE_PASSWORD is not configured.",
      { status: 500 }
    );
  }

  const url = new URL(request.url);

  // パスコード送信
  if (url.pathname === "/__login" && request.method === "POST") {
    const formData = await request.formData();
    const password = formData.get("password");

    if (
      typeof password !== "string" ||
      !(await isValidPassword(password, env.SITE_PASSWORD))
    ) {
      return loginPage("パスコードが正しくありません。");
    }

    const token = await makeToken(env.SITE_PASSWORD);

    return new Response(null, {
      status: 302,
      headers: {
        "Location": "/",
        "Set-Cookie":
          `${COOKIE_NAME}=${token}; Path=/; Max-Age=86400; HttpOnly; Secure; SameSite=Lax`,
        "Cache-Control": "no-store"
      }
    });
  }

  // 認証済みか確認
  const cookie = getCookie(request, COOKIE_NAME);
  const validToken = await makeToken(env.SITE_PASSWORD);

  if (cookie === validToken) {
    return context.next();
  }

  // 未認証ならログイン画面
  return loginPage();
}
