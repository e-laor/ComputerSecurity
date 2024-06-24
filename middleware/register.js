const bcrypt = require('bcrypt');
const User = require('../model/User');
const PasswordHistory = require('../model/PasswordHistory');
const sequelize = require("../model/DB.JS");

async function register(req, res, next) {
  const { username, email, password, confirm_password } = req.body;

  try {
    if (password !== confirm_password) {
      throw new Error("Passwords do not match");
    }
    if (!password || !confirm_password) {
      throw new Error("Passwords can't be empty");
    }

    // Check if the username already exists (vulnerable to SQL injection)
    const checkUsernameQuery = `
      SELECT * FROM Users WHERE username = '${username}'
    `;
    const existingUserByUsername = await sequelize.query(checkUsernameQuery, { raw: true });
    console.log(existingUserByUsername);

    if (existingUserByUsername.length > 0) {
      throw new Error("Username already taken");
    }

    // Check if the email already exists (vulnerable to SQL injection)
    const checkEmailQuery = `
      SELECT * FROM Users WHERE email = '${email}'
    `;
    const existingUserByEmail = await sequelize.query(checkEmailQuery, { raw: true });

    if (existingUserByEmail.length > 0) {
      throw new Error("Email already registered");
    }

    // Hash the password
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Insert the user into Users table (vulnerable to SQL injection)
    const insertUserQuery = `
      INSERT INTO Users (username, email, password)
      VALUES ('${username}', '${email}', '${hashedPassword}')
    `;
    await sequelize.query(insertUserQuery, { raw: true });

    // Optionally, store password history (vulnerable to SQL injection)
    const user = await User.findOne({ where: { username: username } });
    await PasswordHistory.create({
      userId: user.id,
      password: hashedPassword
    });

    req.flash("success", "You have registered successfully.");
    res.redirect("/register");

  } catch (error) {
    console.error('Registration error:', error);
    req.flash("error", error.message);
    res.redirect("/register");
  }
}

module.exports = register;
