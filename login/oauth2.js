require("dotenv").config();
const express = require("express");
const fetch = require("node-fetch");
const crypto = require("crypto");
const cookieSession = require("cookie-session");
const qs = require("querystring");

const {
  CLIENT_ID,
  CLIENT_SECRET,
  AUTHORIZATION_ENDPOINT,
  TOKEN_ENDPOINT,
  USERINFO_ENDPOINT,
  REDIRECT_URI,
  PORT = 3000,
} = process.env;

const app = express();

app.use(
  cookieSession({
    name: "session",
    keys: [crypto.randomBytes(32).toString("hex")],
    maxAge: 24 * 60 * 60 * 1000,
  })
);

// Helpers: PKCE
function base64URLEncode(str) {
  return str
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}
function sha256(buffer) {
  return crypto.createHash("sha256").update(buffer).digest();
}

app.get("/", (req, res) => {
  if (req.session.user) {
    return res.send(`
      <h3>Đã đăng nhập</h3>
      <pre>${JSON.stringify(req.session.user, null, 2)}</pre>
      <a href="/logout">Logout</a>
    `);
  }
  res.send(`<a href="/auth/google/callback">Login with OAuth2 Provider</a>`);
});

app.get("/auth/google/callback", (req, res) => {
  // tạo state chống CSRF
  const state = crypto.randomBytes(16).toString("hex");

  // tạo PKCE code_verifier & code_challenge
  const code_verifier = base64URLEncode(crypto.randomBytes(32));
  const code_challenge = base64URLEncode(sha256(code_verifier));

  // lưu vào session tạm
  req.session.oauth2 = { state, code_verifier };

  const params = {
    response_type: "code",
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    scope: "openid profile email", // tùy provider
    state,
    code_challenge,
    code_challenge_method: "S256",
  };

  const authorizeUrl = `${AUTHORIZATION_ENDPOINT}?${qs.stringify(params)}`;
  res.redirect(authorizeUrl);
});

app.get("/callback", async (req, res) => {
  const { code, state } = req.query;
  if (!req.session.oauth2 || state !== req.session.oauth2.state) {
    return res.status(400).send("Invalid state");
  }

  try {
    // đổi code lấy token
    const body = {
      grant_type: "authorization_code",
      code,
      redirect_uri: REDIRECT_URI,
      client_id: CLIENT_ID,
      // nếu provider yêu cầu client_secret cho server-side:
      client_secret: CLIENT_SECRET,
      code_verifier: req.session.oauth2.code_verifier,
    };

    const tokenResp = await fetch(TOKEN_ENDPOINT, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: qs.stringify(body),
    });
    const tokenData = await tokenResp.json();

    if (tokenData.error) {
      return res.status(400).json(tokenData);
    }

    // tokenData có thể chứa access_token, id_token, refresh_token
    // gọi userinfo nếu có endpoint
    let user = null;
    if (USERINFO_ENDPOINT && tokenData.access_token) {
      const userResp = await fetch(USERINFO_ENDPOINT, {
        headers: { Authorization: `Bearer ${tokenData.access_token}` },
      });
      user = await userResp.json();
    } else if (tokenData.id_token) {
      // tạm decode id_token (JWT) nếu cần (không kiểm tra signature trong ví dụ ngắn)
      const parts = tokenData.id_token.split(".");
      if (parts.length === 3) {
        user = JSON.parse(Buffer.from(parts[1], "base64").toString());
      }
    }

    // lưu session
    req.session.user = { user, tokenData };
    delete req.session.oauth2;
    res.redirect("/");
  } catch (err) {
    console.error(err);
    res.status(500).send("Token exchange failed");
  }
});

app.get("/logout", (req, res) => {
  req.session = null;
  res.redirect("/");
});

app.listen(PORT, () =>
  console.log(`Server running on http://localhost:${PORT}`)
);
