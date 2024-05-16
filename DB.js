// DB.js

const mongoose = require('mongoose');

// Load environment variables from .env file
require("dotenv").config();

// Use the DB_URL environment variable
const uri = process.env.DB_URL;

const connectDB = async () =>
{
  try
  {
    await mongoose.connect(uri);
    console.log('MongoDB connected successfully');
  } catch (error) // any error that occured while attempting to connect to the database
  {
    console.error('MongoDB connection error:', error);
  }
};

module.exports = connectDB;