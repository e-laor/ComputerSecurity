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
const sgMail = require('@sendgrid/mail');

require('dotenv').config();
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

const app = express();

(async () => {
  try {
    await sequelize.sync();
    console.log('Database synchronized successfully.');
  } catch (error) {
    console.error('Database synchronization error:', error);
  }
})();

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

app.use((req, res, next) => {
  res.locals.user = req.user;
  res.locals.error = req.flash("error");
  res.locals.success = req.flash("success");
  next();
});

// Define a custom authentication callback function
passport.use(new LocalStrategy({
  passReqToCallback: true // Pass the request object to the callback
},
async (req, username, password, done) => { // Add req as the first parameter
  try {
    const user = await User.findOne({ where: { username: username } });
    if (!user) {
      return done(null, false, { message: 'Incorrect username.' });
    }

    // Check if the account is locked
    if (user.isLocked) {
      return done(null, false, { message: 'Account is locked. Please contact support.' });
    }

    // Check if the account is locked due to too many failed attempts
    if (req.session.failedLoginAttempts >= 3) {
      // Lock the account
      req.session.failedLoginAttempts = 0;
      user.isLocked = 1;
      await user.save();
      return done(null, false, { message: 'Account locked due to too many failed login attempts. Please contact support.' });
    }

    const isValidPassword = await user.validPassword(password);
    if (!isValidPassword) {
      // Increment failed login attempts on failure
      req.session.failedLoginAttempts += 1;
      return done(null, false, { message: 'Incorrect password.' });
    }

    // Reset failed login attempts on successful login
    req.session.failedLoginAttempts = 0;

    return done(null, user);
  } catch (error) {
    return done(error);
  }
}
));

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

// Middleware to restrict access to specific routes
function restrictDirectAccess(req, res, next) {
  if (!req.session.isLoggedIn && !req.session.allowAccess) {
    req.flash("error", "Unauthorized access.");
    return res.redirect("/login");
  }
  next();
}

//=====================
// ROUTES
//=====================

app.get("/", function (req, res) {
  res.render("home", { title: "Home" });
});

app.get("/secret", isLoggedIn, function (req, res) {
  res.render("secret", { title: "Secret" });
});

function isLoggedIn(req, res, next) {
  if (req.isAuthenticated()) return next();
  req.flash("error", "You must be logged in to access that page.");
  res.redirect("/login");
}

app.get("/register", function (req, res) {
  res.render("register", { title: "Register" });
});

app.post("/register", async (req, res) => {
  try {
    const { username, email, password, confirm_password } = req.body;

    if (password !== confirm_password) {
      throw new Error("Passwords do not match");
    }
    if (!password || !confirm_password) {
      throw new Error("error", "Passwords can't be empty");
    }
    // Check if the username already exists
    const existingUserByUsername = await User.findOne({ where: { username: username } });
    if (existingUserByUsername) {
      req.flash("error", "Username already taken");
      return res.redirect("/register");
    }

    // Check if the email already exists
    const existingUserByEmail = await User.findOne({ where: { email: email } });
    if (existingUserByEmail) {
      req.flash("error", "Email already registered");
      return res.redirect("/register");
    }

       // Check if password length is 10 characters
    if (password.length < 10  || password.length >= 10) {
      req.flash("error", "Password must be 10 characters long");
      return res.redirect("/register");
    }

        // Regex to check for password complexity
    const passwordComplexity = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{10,}$/;

    // Check if password meets complexity requirements
    if (!passwordComplexity.test(password)) {
      req.flash("error", "Password must contain at least one lowercase letter, one uppercase letter, one number, and one special character");
      return res.redirect("/register");
    }
  
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    const user = await User.create({ username, email, password: hashedPassword });
    req.flash("success", "You have registered successfully.");
    res.redirect("/register");
  } catch (error) {
    req.flash("error", error.message);
    res.redirect("/register");
  }
});

app.get("/login", function (req, res) {
  res.render("login", { title: "Login" });
});

app.post("/login", passport.authenticate("local", {
  failureRedirect: "/login",
  failureFlash: true,
}), (req, res) => {
  // If authentication succeeds, set a flag in the session to indicate that the user is logged in
  req.session.isLoggedIn = true;
  req.session.userEmail = req.user.email;
  res.redirect("/");
});

app.get("/logout", function (req, res, next) {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    req.flash("success", "You have logged out successfully.");
    res.redirect("/");
  });
});

app.get("/init-forgot-password", (req, res) => {
  req.session.allowAccess = true;
  res.redirect("/forgot-password");
});

app.get("/forgot-password",restrictDirectAccess, function (req, res) {
  res.render("forgot-password", { title: "Forgot Password" });
});


function generateToken() {
  const token = Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
  return token;
}

app.post("/forgot-password",restrictDirectAccess, async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      throw new Error("Email is required");
    }

    const user = await User.findOne({ where: { email: email } });
    if (!user) {
      throw new Error("User with this email does not exist");
    }

    if (user.isLocked) {
      throw new Error("This User is locked");
    }

    req.session.userEmail=email;
    const token = generateToken();

    user.resetPasswordToken = token;

    const msg = {
      to: email,
      from: process.env.EMAIL_USER, 
      subject: 'Password Reset Request',
      text: `Your password reset token is: ${token}`,
    };

    await user.save();

    sgMail.send(msg)
      .then(() => {
        req.flash("success", "An email has been sent with a token.");
        req.session.allowAccess = true; // Set session variable to allow access
        res.redirect(`/token?email=${email}`); // Redirect to the token route after successfully sending the email
      })
      .catch(error => {
        console.error('Error sending email:', error);
        req.flash("error", "Failed to send email. Please try again later.");
        res.redirect("/forgot-password");
      });

  } catch (error) {
    req.flash("error", error.message); // Display error for wrong email
    res.redirect("/forgot-password");
  }
});


app.get("/token",restrictDirectAccess, function (req, res) {
  const email = req.query.email; // Retrieve email from query parameters
  req.flash("success", "An email has been sent with a token.");
  res.render("token", { title: "Token", email: email, error: req.flash("error"), success: req.flash("success") });
});

app.post("/token",restrictDirectAccess, async (req, res) => {
  try {
    const { token, email } = req.body; // Ensure email is extracted from req.body
    if (!token) {
      req.flash("error", "Token is required");
      return res.render("token", { title: "Token", email: email, error: req.flash("error"), success: req.flash("success") });
    }

    const user = await User.findOne({ where: { email: email } });
    if (!user) {
      req.flash("error", "User not found");
      return res.render("token", { title: "Token", email: email, error: req.flash("error"), success: req.flash("success") });
    }

    if (token !== user.resetPasswordToken) {
      req.flash("error", "Token is invalid");
      return res.render("token", { title: "Token", email: email, error: req.flash("error"), success: req.flash("success") });
    }

    req.flash("success", "Token verified successfully.");
    req.session.allowAccess = true; // Set session variable to allow access
    return res.render("reset-password", { title: "Reset Password", email: email, error: req.flash("error"), success: req.flash("success") });
  } catch (error) {
    req.flash("error", error.message);
    return res.render("token", { title: "Token", email: req.body.email, error: req.flash("error"), success: req.flash("success") });
  }
});
app.get("/reset-password",restrictDirectAccess, function (req, res) {
  const email = req.session.userEmail;
  console.log(email);
  if(!req.session.isLoggedIn){
    req.flash("success", "You entered the correct token, please continue with the password change");}
  res.render("reset-password", { title: "Reset Password", email: email, error: req.flash("error"), success: req.flash("success") });
});

app.post("/reset-password",restrictDirectAccess, async (req, res) => {
  const { password, confirm_password, email } = req.body;
  const user = await User.findOne({ where: { email: email } });
  
  try {
    if (!user) {
      req.flash("error", "User not found.");
      return res.render("reset-password", { title: "Reset Password", email: email, error: req.flash("error"), success: req.flash("success") });
    }

    if (password !== confirm_password) {
      req.flash("error", "Passwords do not match");
      return res.render("reset-password", { title: "Reset Password", email: email, error: req.flash("error"), success: req.flash("success") });
    }
    if (!password || !confirm_password) {
      req.flash("error", "Passwords can't be empty");
      return res.render("reset-password", { title: "Reset Password", email: email, error: req.flash("error"), success: req.flash("success") });
    }
         // Check if password length is 10 characters
    if (password.length < 10  || password.length >= 10) {
      req.flash("error", "Password must be 10 characters long");
      return res.redirect("/reset-password");
    }

        // Regex to check for password complexity
    const passwordComplexity = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{10,}$/;

    // Check if password meets complexity requirements
    if (!passwordComplexity.test(password)) {
      req.flash("error", "Password must contain at least one lowercase letter, one uppercase letter, one number, and one special character");
      return res.redirect("/reset-password");
    }
  
    const hashedPassword = await bcrypt.hash(password, 10);
    user.password = hashedPassword;
    user.resetPasswordToken = null;
    user.resetPasswordExpires = null;
    await user.save();

    req.session.allowAccess = false; // Clear session variable to prevent further access
    return res.redirect("/reset-password-success"); // Redirect to success page
  } catch (error) {
    req.flash("error", error.message);
    return res.render("reset-password", { title: "Reset Password", email: email, error: req.flash("error"), success: req.flash("success") });
  }
});

app.get("/reset-password-success", function (req, res) {
  res.render("reset-password-success", { title: "Password Reset Successful" });
});

const port = process.env.PORT || 3000;
app.listen(port, function () {
  console.log("Server Has Started!");
});
