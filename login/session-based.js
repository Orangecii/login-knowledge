const express = require("express");
const session = require("express-session");

const app = express();

// Middleware để parse JSON và form data
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(
  session({
    secret: "mySecretKey", // Khóa bí mật để mã hóa session ID
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false }, // Để true nếu chạy HTTPS
  })
);

// Login route
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  if (username === "admin" && password === "123456") {
    req.session.user = { username }; // Lưu vào session
    return res.send("Login thành công!");
  }
  res.status(401).send("Sai thông tin đăng nhập!");
});

// Protected route
app.get("/dashboard", (req, res) => {
  if (req.session.user) {
    return res.send(`Xin chào ${req.session.user.username}`);
  }
  res.status(401).send("Bạn chưa đăng nhập!");
});

// Logout
app.post("/logout", (req, res) => {
  req.session.destroy(() => {
    res.send("Đã logout!");
  });
});

app.listen(3000, () => console.log("Server chạy ở http://localhost:3000"));
