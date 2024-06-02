const { DataTypes } = require('sequelize');
const sequelize = require('./DB');

const Client = sequelize.define('Client', {
    name: {
    type: DataTypes.STRING,
    unique: true,
    allowNull: false,
  },
  email: {
      type: DataTypes.STRING,
      unique: true,
      allowNull: false,
    },
    phone: {
      type: DataTypes.STRING,
      allowNull: false,
    }
});

module.exports = Client;