const register = require('./register');
const forgot_password = require("./forgot_password");
const token = require("./token");
const reset_password = require('./reset_password');

module.exports = {
  register,
  forgot_password,
  token,
  reset_password
};
