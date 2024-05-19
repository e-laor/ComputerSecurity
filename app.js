// app.js

const express = require("express");
const bodyParser = require("body-parser");
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const crypto = require('crypto');
const User = require("./model/User");
const sequelize = require("./model/DB");
const bcrypt = require('bcrypt');

const app = express();

// Synchronize models with the database
(async () => {
  try {
    // This will create the tables if they don't already exist
    await sequelize.sync();
    console.log('Database synchronized successfully.');
  } catch (error) {
    console.error('Database synchronization error:', error);
  }
})();

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

// Configure passport to use LocalStrategy
passport.use(new LocalStrategy(async (username, password, done) => {
  try {
    const user = await User.findOne({ where: { username: username } });
    if (!user) {
      return done(null, false, { message: 'Incorrect username.' });
    }
    const isValidPassword = await user.validPassword(password);
    if (!isValidPassword) {
      return done(null, false, { message: 'Incorrect password.' });
    }
    return done(null, user);
  } catch (error) {
    return done(error);
  }
}));

// Configure passport to maintain user session
passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findByPk(id);
    done(null, user);
  } catch (error) {
    done(error);
  }
});

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

// Handling user signup
app.post("/register", async (req, res) => {
  try {
    const saltRounds = 10; // This determines the complexity of the hash
    const hashedPassword = await bcrypt.hash(req.body.password, saltRounds);
    const user = await User.create({ username: req.body.username, email: req.body.email, password: hashedPassword });
    res.status(200).json(user);
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

const port = process.env.PORT || 3000;
app.listen(port, function () {
  console.log("Server Has Started!");
});
