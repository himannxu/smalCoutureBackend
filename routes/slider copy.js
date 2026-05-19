const express = require("express");
const SliderSlide = require("../models/SliderSlide");
const { nextNumericId } = require("../utils/nextNumericId");

const router = express.Router();

// Slider JSON is URLs only; hero crop/fit is handled in the storefront
// (src/components/HeaderSection/Slider.jsx) so full artwork can show edge-to-edge.

// GET /api/slider
router.get("/slider", async (req, res) => {
  try {
    const slides = await SliderSlide.find().sort({ id: 1 }).lean();
    res.json(slides);
  } catch (err) {
    console.error("Error fetching slider slides", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// POST /api/admin/slider
function normalizeSliderCategoryId(value) {
  if (value === undefined || value === null || value === "") return null;
  const n = Number(value);
  return Number.isFinite(n) ? n : null;
}

router.post("/admin/slider", async (req, res) => {
  try {
    const { title, subtitle, imageUrl, categoryId: rawCategoryId } = req.body;

    if (
      !title ||
      !subtitle ||
      !Array.isArray(subtitle) ||
      subtitle.length === 0 ||
      !imageUrl
    ) {
      return res.status(400).json({
        error: "title, subtitle (array), and imageUrl are required",
      });
    }

    const nextId = await nextNumericId(SliderSlide, "id");

    const doc = await SliderSlide.create({
      id: nextId,
      title,
      subtitle,
      images: imageUrl,
      categoryId: normalizeSliderCategoryId(rawCategoryId),
    });

    return res.status(201).json(doc.toObject());
  } catch (err) {
    console.error("Error creating slider slide", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

module.exports = router;

