import express from "express";
import session from "express-session";
import bodyParser from "body-parser";
import { dirname } from "path";
import { fileURLToPath } from "url";
import bcrypt from "bcrypt";

const app = express();
const __dirname = dirname(fileURLToPath(import.meta.url));

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(
  session({
    secret: "your-secret-key",
    resave: false,
    saveUninitialized: true,
  })
);

const users = [];

const isAuthenticated = (req, res, next) => {
  if (req.session.isAuthenticated) {
    return next();
  }
  res.redirect("/?error=unauthenticated");
};

app.get("/", (req, res) => {
  res.sendFile(__dirname + "/views/index.html");
});

app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  users.push({ username, password: hashedPassword });
  res.redirect("/");
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const user = users.find((user) => user.username === username);

  if (!user) {
    return res.redirect("/?error=user-not-found");
  }

  const valid = await bcrypt.compare(password, user.password);

  if (user && valid) {
    req.session.isAuthenticated = true;
    return res.redirect("/secured");
  } else {
    return res.redirect("/?error=invalid-password-or-username");
  }
});

app.get("/secured", isAuthenticated, (req, res) => {
  res.sendFile(__dirname + "/views/secured.html");
});

app.get("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error(err);
    }
    res.redirect("/");
  });
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
