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
const flash = require("connect-flash");

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

app.use(flash());
app.use(passport.initialize());
app.use(passport.session());

// Middleware to make 'user' and 'flash messages' available in all templates
app.use((req, res, next) => {
  res.locals.user = req.user;
  res.locals.error = req.flash("error");
  res.locals.success = req.flash("success");
  next();
});


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
    const { username, email, password, confirm_password } = req.body;

    // Check if passwords match
    if (password !== confirm_password) {
      throw new Error("Passwords do not match");
    }

    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    const user = await User.create({ username, email, password: hashedPassword });
    req.flash("success", "You have registered successfully.");
    //res.status(200).json(user);
    res.redirect("/register");
  } catch (error) {
    req.flash("error", error.message);
    res.redirect("/register");
    //res.status(400).json({ error: error.message });
  }
});

// Showing login form
app.get("/login", function (req, res) {
  res.render("login", { title: "Login" });
});

// Handling user login
app.post("/login", passport.authenticate("local", {
  successRedirect: "/",
  failureRedirect: "/login",
  failureFlash: true,
}));

// Handling user logout
app.get("/logout", function (req, res, next) {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    req.flash("success", "You have logged out successfully.");
    res.redirect("/");
  });
});

function isLoggedIn(req, res, next) {
  if (req.isAuthenticated()) return next();
  req.flash("error", "You must be logged in to access that page.");
  res.redirect("/login");
}

const port = process.env.PORT || 3000;
app.listen(port, function () {
  console.log("Server Has Started!");
});
