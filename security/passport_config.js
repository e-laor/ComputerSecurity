// used for handling account login

const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const User = require("../model/User");
const sequelize = require("../model/DB.JS");

passport.use(
  new LocalStrategy(
    {
      passReqToCallback: true,
    },
    async (req, username, password, done) => {
      try {
        // Vulnerable query: directly using interpolated values
        //example for sql injection: ' OR '1'='1
        const query = `SELECT * FROM Users WHERE username = '${username}'`;
        console.log("query", query);
        const user = await sequelize.query(query, { model: User });
        console.log("user", user);

        if (!user || !user.length) {
          return done(null, false, { message: "Incorrect username." });
        }

        const isValidPassword = await user[0].validPassword(password);
        if (!isValidPassword) {
          return done(null, false, { message: "Incorrect password." });
        }

        // Reset failed login attempts on successful login
        req.session.failedLoginAttempts = 0;

        return done(null, user[0]); // If authentication succeeds
      } catch (error) {
        return done(error);
      }
    }
  )
);

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

module.exports = passport;
