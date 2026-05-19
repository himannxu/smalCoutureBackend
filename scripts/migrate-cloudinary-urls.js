/**
 * One-time migration: download Cloudinary images → server uploads/ folder,
 * replace all res.cloudinary.com URLs in Website2 with PUBLIC_BASE_URL/uploads/...
 *
 * Usage:
 *   node scripts/migrate-cloudinary-urls.js           # run migration
 *   node scripts/migrate-cloudinary-urls.js --dry-run # count only
 *
 * Requires .env: MONGODB_URI, optional PUBLIC_BASE_URL (default https://api.smalcouture.com)
 */
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
require("dotenv").config({ path: path.join(__dirname, "..", ".env") });

const axios = require("axios");
const mongoose = require("mongoose");

const DRY_RUN = process.argv.includes("--dry-run");
const PUBLIC_BASE = String(
  process.env.PUBLIC_BASE_URL || "https://api.smalcouture.com",
).replace(/\/$/, "");
const UPLOAD_DIR = path.join(__dirname, "..", "uploads");
const MAP_FILE = path.join(__dirname, "..", ".cloudinary-url-map.json");

const CLOUDINARY_RE = /https?:\/\/res\.cloudinary\.com\/[^\s"'<>\\]+/gi;
const EXT_BY_MIME = {
  "image/jpeg": ".jpg",
  "image/jpg": ".jpg",
  "image/png": ".png",
  "image/webp": ".webp",
  "image/gif": ".gif",
  "image/svg+xml": ".svg",
};

function ensureUploadDir() {
  if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}

function loadMap() {
  if (!fs.existsSync(MAP_FILE)) return {};
  try {
    return JSON.parse(fs.readFileSync(MAP_FILE, "utf8"));
  } catch {
    return {};
  }
}

function saveMap(map) {
  fs.writeFileSync(MAP_FILE, JSON.stringify(map, null, 2));
}

function cleanUrl(url) {
  return String(url).replace(/[)\]},.]+$/, "");
}

function extFromUrl(url) {
  const m = url.match(/\.(jpe?g|png|webp|gif|svg)(?:\?|$)/i);
  if (!m) return ".jpg";
  const e = m[1].toLowerCase();
  if (e === "jpeg") return ".jpg";
  return `.${e}`;
}

async function downloadImage(url) {
  const res = await axios.get(url, {
    responseType: "arraybuffer",
    timeout: 60000,
    maxRedirects: 5,
    validateStatus: (s) => s >= 200 && s < 400,
  });
  const mime = String(res.headers["content-type"] || "").split(";")[0].trim();
  const ext = EXT_BY_MIME[mime] || extFromUrl(url);
  return { buffer: Buffer.from(res.data), ext };
}

async function migrateUrl(oldUrl, map) {
  const url = cleanUrl(oldUrl);
  if (map[url]) return map[url];
  if (map[url] === null) return url; // previously failed — keep Cloudinary URL

  if (DRY_RUN) {
    map[url] = `${PUBLIC_BASE}/uploads/DRY_RUN`;
    return map[url];
  }

  const hash = crypto.createHash("md5").update(url).digest("hex");
  let ext = extFromUrl(url);
  let filename = `${hash}${ext}`;
  let filepath = path.join(UPLOAD_DIR, filename);

  if (!fs.existsSync(filepath)) {
    try {
      const { buffer, ext: detectedExt } = await downloadImage(url);
      ext = detectedExt;
      filename = `${hash}${ext}`;
      filepath = path.join(UPLOAD_DIR, filename);
      fs.writeFileSync(filepath, buffer);
    } catch (err) {
      console.error(`FAIL download (skipped): ${url}`, err.message);
      map[url] = null;
      saveMap(map);
      return url;
    }
  }

  const newUrl = `${PUBLIC_BASE}/uploads/${filename}`;
  map[url] = newUrl;
  saveMap(map);
  return newUrl;
}

function collectUrls(val, set) {
  if (typeof val === "string") {
    const matches = val.match(CLOUDINARY_RE);
    if (matches) matches.forEach((u) => set.add(cleanUrl(u)));
    return;
  }
  if (Array.isArray(val)) val.forEach((v) => collectUrls(v, set));
  else if (val && typeof val === "object") {
    if (val._bsontype === "ObjectID" || val._bsontype === "ObjectId") return;
    if (val instanceof Date) return;
    Object.values(val).forEach((v) => collectUrls(v, set));
  }
}

async function replaceValue(val, map) {
  if (typeof val === "string") {
    if (!val.includes("cloudinary")) return val;
    let out = val;
    const matches = [...new Set(val.match(CLOUDINARY_RE) || [])];
    for (const raw of matches) {
      const u = cleanUrl(raw);
      const next = await migrateUrl(u, map);
      out = out.split(raw).join(next);
    }
    return out;
  }
  if (Array.isArray(val)) {
    const arr = [];
    for (const item of val) arr.push(await replaceValue(item, map));
    return arr;
  }
  if (val && typeof val === "object") {
    if (val._bsontype === "ObjectID" || val._bsontype === "ObjectId") return val;
    if (val instanceof Date) return val;
    const out = {};
    for (const [k, v] of Object.entries(val)) {
      out[k] = await replaceValue(v, map);
    }
    return out;
  }
  return val;
}

function docsEqual(a, b) {
  return JSON.stringify(a) === JSON.stringify(b);
}

async function main() {
  const uri = (process.env.MONGODB_URI || "").trim();
  if (!uri) {
    console.error("MONGODB_URI missing in .env");
    process.exit(1);
  }

  ensureUploadDir();
  const map = loadMap();

  console.log(`Mode: ${DRY_RUN ? "DRY RUN" : "LIVE"}`);
  console.log(`Public base: ${PUBLIC_BASE}`);
  console.log(`Upload dir: ${UPLOAD_DIR}`);

  await mongoose.connect(uri);
  const db = mongoose.connection.db;

  const allUrls = new Set();
  const collections = await db.listCollections().toArray();
  for (const { name } of collections) {
    const docs = await db.collection(name).find({}).toArray();
    docs.forEach((d) => collectUrls(d, allUrls));
  }
  console.log(`Found ${allUrls.size} unique Cloudinary URL(s) in database.`);

  if (DRY_RUN) {
    await mongoose.disconnect();
    return;
  }

  let downloaded = 0;
  let updatedDocs = 0;
  const urlList = [...allUrls];
  for (let i = 0; i < urlList.length; i++) {
    const u = urlList[i];
    if (map[u] === undefined) {
      const before = map[u];
      await migrateUrl(u, map);
      if (map[u] && map[u] !== null) downloaded++;
      if ((i + 1) % 25 === 0 || i === urlList.length - 1) {
        console.log(`Processed ${i + 1}/${urlList.length} URL(s)...`);
      }
    }
  }
  const ok = Object.values(map).filter((v) => v && v !== null).length;
  const failed = Object.values(map).filter((v) => v === null).length;
  console.log(`Mapped: ${ok} OK, ${failed} failed (kept Cloudinary), ${downloaded} new file(s).`);

  for (const { name } of collections) {
    const col = db.collection(name);
    const cursor = col.find({});
    let colUpdated = 0;
    for await (const doc of cursor) {
      const next = await replaceValue(doc, map);
      if (!docsEqual(doc, next)) {
        await col.replaceOne({ _id: doc._id }, next);
        colUpdated++;
      }
    }
    if (colUpdated > 0) {
      console.log(`Updated ${colUpdated} document(s) in ${name}`);
      updatedDocs += colUpdated;
    }
  }

  console.log(`Done. ${updatedDocs} document(s) updated across ${collections.length} collection(s).`);
  console.log(`Copy uploads/ folder to production server if you ran this locally.`);
  await mongoose.disconnect();
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
