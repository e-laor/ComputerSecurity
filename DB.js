// DB.js

const mongoose = require('mongoose');
require("dotenv").config();
const uri = process.env.DB_URL;

const connectDB = async () => {
  try {
    await mongoose.connect(uri);
    console.log('MongoDB connected successfully');
  } catch (error) {
    console.error('MongoDB connection error:', error);
  }
};

module.exports = connectDB;
