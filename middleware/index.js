const register = require('./register');
const forgot_password = require("./forgot_password");
const token = require("./token");
const change_password = require('./change_password');

module.exports = {
  register,
  forgot_password,
  token,
  change_password
};
