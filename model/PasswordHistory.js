const { DataTypes } = require('sequelize');
const sequelize = require('./DB');

const Password = sequelize.define('Password', {
  userId: {
    type: DataTypes.INTEGER,
    allowNull: false,
  },
  password: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  changeDate: {
    type: DataTypes.DATE,
    defaultValue: DataTypes.NOW
  },
});

module.exports = Password;
