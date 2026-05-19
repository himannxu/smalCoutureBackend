const mongoose = require("mongoose");

// Simple shape matching frontend: { id, title, count, image }
const categorySchema = new mongoose.Schema(
  {
    id: { type: Number, required: true, index: true, unique: true },
    title: { type: String, required: true },
    count: { type: String, default: "0" },
    image: { type: String, required: true },
  },
  { timestamps: true },
);

module.exports = mongoose.model("Category", categorySchema, "categories");

