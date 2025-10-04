import express from "express";

const app = express();
const PORT = 3000;

// Giả sử user hợp lệ là:
const VALID_USER = { username: "admin", password: "1234" };

// Middleware kiểm tra Basic Auth
function basicAuth(req, res, next) {
  // Lấy header Authorization
  const authHeader = req.headers["authorization"];
  if (!authHeader) {
    res.set("WWW-Authenticate", 'Basic realm="Access to the site"');
    return res.status(401).send("Authorization required");
  }

  // authHeader có dạng: "Basic base64(username:password)"
  const base64Credentials = authHeader.split(" ")[1];
  const credentials = Buffer.from(base64Credentials, "base64").toString(
    "utf-8"
  );
  const [username, password] = credentials.split(":");

  // Kiểm tra username/password
  if (username === VALID_USER.username && password === VALID_USER.password) {
    req.user = { username };
    return next();
  }

  return res.status(401).send("Invalid credentials");
}

// Route được bảo vệ
app.get("/protected", basicAuth, (req, res) => {
  res.send(`Hello ${req.user.username}, you have access!`);
});

// Route public (không cần login)
app.get("/", (req, res) => {
  res.send("Public route, no authentication needed.");
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
