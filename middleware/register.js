const bcrypt = require('bcrypt');
const User = require('../model/User');
const pass_secure = require("../security/pass_security");
const PasswordHistory = require('../model/PasswordHistory');

async function register(req, res, next) {
  try {
    const { username, email, password, confirm_password } = req.body;

    if (password !== confirm_password) {
      throw new Error("Passwords do not match");
    }
    if (!password || !confirm_password) {
      throw new Error("Passwords can't be empty");
    }
    // Check if the username already exists
    const existingUserByUsername = await User.findOne({
      where: { username: username },
    });
    if (existingUserByUsername) {
      throw new Error("Username already taken");
    }

    // Check if the email already exists
    const existingUserByEmail = await User.findOne({ where: { email: email } });
    if (existingUserByEmail) {
      throw new Error("Email already registered");
    }

    // check password strength
    const isValidPassword = pass_secure.isPasswordStrong(password);

    // if password isn't strong enough throw an error with the message
    if (!isValidPassword.isValid) {
      throw new Error(isValidPassword.message);
    }

    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    const user = await User.create({
      username,
      email,
      password: hashedPassword,
    });
    await PasswordHistory.create({
      userId: user.id,
      password: hashedPassword
    })
    req.flash("success", "You have registered successfully.");
    res.redirect("/register");
  } catch (error) {
    req.flash("error", error.message);
    res.redirect("/register");
  }
}

module.exports = register;
