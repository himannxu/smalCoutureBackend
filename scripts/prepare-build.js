/**
 * Creates build/ with only runtime files needed inside the Docker image.
 * Dev-only files (node_modules, .env, uploads, scripts, copies) stay out.
 */
const fs = require("fs");
const path = require("path");

const ROOT = path.join(__dirname, "..");
const OUT = path.join(ROOT, "build");

const COPY_PATHS = [
  "index.js",
  "package.json",
  "package-lock.json",
  "models",
  "routes",
  "utils",
  "data",
];

const SKIP_NAMES = new Set(["Untitled", ".DS_Store"]);
const SKIP_SUFFIXES = [" copy.js", " copy"];

function shouldSkip(name) {
  if (SKIP_NAMES.has(name)) return true;
  return SKIP_SUFFIXES.some((suffix) => name.endsWith(suffix));
}

function rmrf(dir) {
  if (fs.existsSync(dir)) fs.rmSync(dir, { recursive: true, force: true });
}

function copyRecursive(src, dest) {
  const stat = fs.statSync(src);
  if (stat.isDirectory()) {
    fs.mkdirSync(dest, { recursive: true });
    for (const entry of fs.readdirSync(src)) {
      if (shouldSkip(entry)) continue;
      copyRecursive(path.join(src, entry), path.join(dest, entry));
    }
    return;
  }
  fs.mkdirSync(path.dirname(dest), { recursive: true });
  fs.copyFileSync(src, dest);
}

rmrf(OUT);
fs.mkdirSync(OUT, { recursive: true });
fs.mkdirSync(path.join(OUT, "uploads"), { recursive: true });
fs.writeFileSync(path.join(OUT, "uploads", ".gitkeep"), "");

for (const rel of COPY_PATHS) {
  const src = path.join(ROOT, rel);
  if (!fs.existsSync(src)) {
    console.warn(`Skipping missing path: ${rel}`);
    continue;
  }
  copyRecursive(src, path.join(OUT, rel));
}

const mapSrc = path.join(ROOT, ".cloudinary-url-map.json");
if (fs.existsSync(mapSrc)) {
  fs.copyFileSync(mapSrc, path.join(OUT, ".cloudinary-url-map.json"));
  console.log("Included .cloudinary-url-map.json for auto upload sync on start");
} else {
  console.warn("No .cloudinary-url-map.json — run migrate:cloudinary once locally, then commit the file");
}

console.log(`Deploy build ready at ${OUT}`);
