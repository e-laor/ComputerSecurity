const express = require("express"),
  mongoose = require("mongoose"),
  passport = require("passport"),
  bodyParser = require("body-parser"),
  LocalStrategy = require("passport-local"),
  passportLocalMongoose = require("passport-local-mongoose"),
  session = require("express-session");
const User = require("./model/User");
const crypto = require('crypto');
const connectDB = require("./DB");

let app = express();
connectDB();

// Serve static files from the "public" directory
app.use(express.static(__dirname + "/public"));

app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
  secret: crypto.randomBytes(64).toString('hex'),
  resave: false,
  saveUninitialized: false,
}));

app.use(passport.initialize());
app.use(passport.session());

passport.use(new LocalStrategy(User.authenticate()));
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

// Middleware to make 'user' available in all templates
app.use((req, res, next) => {
  res.locals.user = req.user;
  next();
});

app.use((req, res, next) => {
  console.log(`Request URL: ${req.url}`);
  next();
});
//=====================
// ROUTES
//=====================

// Showing home page
app.get("/", function (req, res) {
  res.render("home", { title: "Home" });
});

// Showing secret page
app.get("/secret", isLoggedIn, function (req, res) {
  res.render("secret", { title: "Secret" });
});

// Showing register form
app.get("/register", function (req, res) {
  res.render("register", { title: "Register" });
});

// Middleware to make 'user' available in all templates
app.use((req, res, next) => {
  res.locals.user = req.user;
  next();
});

// Handling user signup
app.post("/register", async (req, res) => {
  try {
    const user = new User({ username: req.body.username, email: req.body.email });
    const registeredUser = await User.register(user, req.body.password);
    res.status(200).json(registeredUser);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Showing login form
app.get("/login", function (req, res) {
  res.render("login", { title: "Login" });
});

// Handling user login
app.post("/login", passport.authenticate("local", {
  successRedirect: "/secret",
  failureRedirect: "/login",
  failureFlash: true
}));

// Handling user logout
app.get("/logout", function (req, res, next) {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

function isLoggedIn(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.redirect("/login");
}

let port = process.env.PORT || 3000;
app.listen(port, function () {
  console.log("Server Has Started!");
});


