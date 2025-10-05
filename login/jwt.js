const express = require("express");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json());


const SECRET_KEY = "mysecretkey";

// Đăng nhập -> cấp token
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  // Giả sử xác thực thành công
  const token = jwt.sign({ username }, SECRET_KEY, { expiresIn: "1h" });
  res.json({ token });
});

// Middleware kiểm tra token
function verifyToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) return res.status(401).json({ message: "Missing token" });

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.status(403).json({ message: "Invalid token" });
    req.user = user;
    next();
  });
}

// Route được bảo vệ
app.get("/profile", verifyToken, (req, res) => {
  res.json({ message: `Welcome ${req.user.username}` });
});

app.listen(3000);
