const express = require("express");
const bodyParser = require("body-parser");
const session = require("express-session");
const LocalStrategy = require("passport-local").Strategy;
const crypto = require("crypto");
const Client = require("./model/Client");
const sequelize = require("./model/DB");
const flash = require("connect-flash");
const sgMail = require("@sendgrid/mail");
const passport = require("./security/passport_config");
const middleware = require("./middleware");
const { get } = require("https");

require("dotenv").config();
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

const app = express();

(async () => {
  try {
    await sequelize.sync();
    console.log("Database synchronized successfully.");
  } catch (error) {
    console.error("Database synchronization error:", error);
  }
})();

app.use(express.static(__dirname + "/public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));
app.use(
  session({
    secret: crypto.randomBytes(64).toString("hex"),
    resave: false,
    saveUninitialized: false,
  })
);
app.use(flash());
app.use(passport.initialize());
app.use(passport.session());

app.use((req, res, next) => {
  res.locals.user = req.user;
  res.locals.error = req.flash("error");
  res.locals.success = req.flash("success");
  next();
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
// -- register route ---
app.get("/register", function (req, res) {
  res.render("register", { title: "Register" });
});

app.post("/register", middleware.register);

// ---- login route --- //

app.get("/login", function (req, res) {
  res.render("login", { title: "Login" });
});

app.post(
  "/login",
  passport.authenticate("local", {
    failureRedirect: "/login",
    failureFlash: true,
  }),
  (req, res) => {
    // If authentication succeeds, set a flag in the session to indicate that the user is logged in
    req.session.isLoggedIn = true;
    req.session.userEmail = req.user.email;
    res.redirect("/");
  }
);

// ---- logout route --- //

app.get("/logout", function (req, res, next) {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    req.flash("success", "You have logged out successfully.");
    res.redirect("/");
  });
});

// ---- forgot password route --- //

app.get("/init-forgot-password", (req, res) => {
  req.session.allowAccess = true;
  res.redirect("/forgot-password");
});

app.get("/forgot-password", restrictDirectAccess, function (req, res) {
  res.render("forgot-password", { title: "Forgot Password" });
});


app.post("/forgot-password", restrictDirectAccess, middleware.forgot_password);

// ---- token route --- //

app.get("/token", restrictDirectAccess, function (req, res) {
  const email = req.query.email; // Retrieve email from query parameters
  req.flash("success", "An email has been sent with a token.");
  res.render("token", {
    title: "Token",
    email: email,
    error: req.flash("error"),
    success: req.flash("success"),
  });
});

app.post("/token", restrictDirectAccess, middleware.token);

// ---- change password route --- //
app.get("/change_password", restrictDirectAccess, function (req, res) {
  const email = req.session.userEmail;
  if (!req.session.isLoggedIn) {
    req.flash(
      "success",
      "You entered the correct token, please continue with the password change"
    );
  }
  res.render("change_password", {
    title: "Change Password",
    email: email,
    error: req.flash("error"),
  });
});

app.post("/change_password", restrictDirectAccess, middleware.change_password);

app.get("/change_password_success", restrictDirectAccess, function (req, res) {
  res.render("change_password_success"); // Corrected "success"
});

// ---- system route --- //

app.get("/system", restrictDirectAccess, async (req, res) => {
  try {
    const clients = await Client.findAll(); // Fetch all clients from the database
    const error = req.query.error; // Retrieve error from query parameters
    res.render("system", {
      title: "Add a new client",
      clients: clients,
      error: error, // Pass error message to template
    });
  } catch (error) {
    console.log("Error fetching clients:", error); // Log the error to see what went wrong
    res.redirect("/system?error=Unable to fetch clients.");
  }
});

app.post("/system", restrictDirectAccess, async (req, res) => {
  try {
    const { clientName, clientEmail, clientPhone } = req.body;

    // Simulate a vulnerable query (DO NOT USE IN PRODUCTION)
    const insertClientQuery = `
      INSERT INTO Clients (name, email, phone)
      VALUES ('${clientName}', '${clientEmail}', '${clientPhone}')
    `;

    // Vulnerable execution of raw SQL query (DO NOT USE IN PRODUCTION)
    await sequelize.query(insertClientQuery, { raw: true });

    console.log(`New client created with name: ${clientName}`);
    res.redirect(`/system-success?name=${encodeURIComponent(clientName)}`);
  } catch (error) {
    console.error("Error inserting client:", error.errors[0].message);
    res.redirect(`/system?error=${encodeURIComponent(error.errors[0].message)}`);
  }
});


// ---- add client successfully route --- //

app.get("/system-success", restrictDirectAccess, async (req, res) => {
  const clientName = req.query.name; // Retrieve the client's name from the query parameter
  const searchQuery = req.query.q; // Retrieve the search query from the query parameter

  let clients = [];

  if (searchQuery) {
    try {
      // Vulnerable query for demonstration purposes
      const query = `SELECT * FROM Clients WHERE name LIKE '%${searchQuery}%'`;
      clients = await sequelize.query(query, { model: Client });
    } catch (error) {
      req.flash('error', 'An error occurred while searching for clients.');
    }
  }

  res.render("system-success", {
    title: "Client Added",
    clientName: clientName,
    clients: clients,
    error: req.flash('error')
  });
});

//=====================
// END OF ROUTES
//=====================

const port = process.env.PORT || 3000;
app.listen(port, function () {
  console.log("Server Has Started!");
});
