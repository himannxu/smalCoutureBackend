async function nextNumericId(Model, field = "id") {
  const last = await Model.findOne().sort({ [field]: -1 }).lean();
  const lastValue = last && typeof last[field] === "number" ? last[field] : 0;
  return lastValue + 1;
}

module.exports = { nextNumericId };

