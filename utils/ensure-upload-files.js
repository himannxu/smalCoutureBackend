/**
 * On server start: download any missing /uploads/* files from Cloudinary (using .cloudinary-url-map.json).
 * No extra CLI needed — runs in background when you npm start.
 */
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const axios = require("axios");

const MAP_FILE = path.join(__dirname, "..", ".cloudinary-url-map.json");
const UPLOAD_PATH_RE = /\/uploads\/([a-zA-Z0-9._-]+)/gi;
const CLOUDINARY_RE = /https?:\/\/res\.cloudinary\.com\/[^\s"'<>\\]+/gi;

const EXT_BY_MIME = {
  "image/jpeg": ".jpg",
  "image/jpg": ".jpg",
  "image/png": ".png",
  "image/webp": ".webp",
  "image/gif": ".gif",
  "image/svg+xml": ".svg",
};

function loadMap() {
  if (!fs.existsSync(MAP_FILE)) return {};
  try {
    return JSON.parse(fs.readFileSync(MAP_FILE, "utf8"));
  } catch {
    return {};
  }
}

function buildReverseMap(map) {
  const reverse = {};
  for (const [cloudUrl, localUrl] of Object.entries(map)) {
    if (!localUrl || localUrl === null) continue;
    const m = String(localUrl).match(/\/uploads\/([^/?#]+)/i);
    if (m) reverse[decodeURIComponent(m[1])] = cloudUrl;
  }
  return reverse;
}

function extFromUrl(url) {
  const m = String(url).match(/\.(jpe?g|png|webp|gif|svg)(?:\?|$)/i);
  if (!m) return ".jpg";
  const e = m[1].toLowerCase();
  return e === "jpeg" ? ".jpg" : `.${e}`;
}

async function downloadToFile(url, filepath) {
  const res = await axios.get(url, {
    responseType: "arraybuffer",
    timeout: 60000,
    maxRedirects: 5,
    validateStatus: (s) => s >= 200 && s < 400,
  });
  let finalPath = filepath;
  if (!path.extname(filepath)) {
    const mime = String(res.headers["content-type"] || "").split(";")[0].trim();
    const ext = EXT_BY_MIME[mime] || extFromUrl(url);
    finalPath = `${filepath}${ext}`;
  }
  fs.mkdirSync(path.dirname(finalPath), { recursive: true });
  fs.writeFileSync(finalPath, Buffer.from(res.data));
  return finalPath;
}

function collectFromValue(val, uploadNames, cloudUrls) {
  if (typeof val === "string") {
    let m;
    UPLOAD_PATH_RE.lastIndex = 0;
    while ((m = UPLOAD_PATH_RE.exec(val)) !== null) {
      uploadNames.add(decodeURIComponent(m[1]));
    }
    const clouds = val.match(CLOUDINARY_RE);
    if (clouds) clouds.forEach((u) => cloudUrls.add(u.replace(/[)\]},.]+$/, "")));
    return;
  }
  if (Array.isArray(val)) val.forEach((v) => collectFromValue(v, uploadNames, cloudUrls));
  else if (val && typeof val === "object") {
    if (val._bsontype === "ObjectID" || val._bsontype === "ObjectId") return;
    if (val instanceof Date) return;
    Object.values(val).forEach((v) => collectFromValue(v, uploadNames, cloudUrls));
  }
}

async function ensureUploadFiles({ uploadDir, db }) {
  if (process.env.SKIP_UPLOAD_SYNC === "1") return;

  const map = loadMap();
  const reverse = buildReverseMap(map);
  const uploadNames = new Set();
  const cloudUrls = new Set();

  for (const [filename, cloudUrl] of Object.entries(reverse)) {
    uploadNames.add(filename);
    cloudUrls.add(cloudUrl);
  }

  if (db) {
    const collections = await db.listCollections().toArray();
    for (const { name } of collections) {
      const docs = await db.collection(name).find({}).toArray();
      docs.forEach((d) => collectFromValue(d, uploadNames, cloudUrls));
    }
  }

  let downloaded = 0;
  let skipped = 0;

  for (const filename of uploadNames) {
    const filepath = path.join(uploadDir, filename);
    if (fs.existsSync(filepath)) continue;

    const cloudUrl = reverse[filename];
    if (!cloudUrl) {
      skipped++;
      continue;
    }

    try {
      await downloadToFile(cloudUrl, filepath);
      downloaded++;
    } catch (err) {
      console.warn(`[uploads] could not fetch ${filename}:`, err.message);
    }
  }

  for (const cloudUrl of cloudUrls) {
    const hash = crypto.createHash("md5").update(cloudUrl).digest("hex");
    const filepath = path.join(uploadDir, `${hash}${extFromUrl(cloudUrl)}`);
    if (fs.existsSync(filepath)) continue;
    try {
      await downloadToFile(cloudUrl, filepath);
      downloaded++;
    } catch (err) {
      console.warn(`[uploads] could not fetch cloudinary asset:`, err.message);
    }
  }

  if (downloaded > 0) {
    console.log(`[uploads] Downloaded ${downloaded} missing file(s) into ${uploadDir}`);
  } else if (uploadNames.size > 0 && skipped === 0) {
    console.log(`[uploads] All ${uploadNames.size} mapped file(s) already on disk`);
  } else if (skipped > 0 && downloaded === 0) {
    console.log(
      `[uploads] ${skipped} DB file(s) missing locally with no Cloudinary map — add .cloudinary-url-map.json`,
    );
  }
}

function ensureUploadFilesAsync(opts) {
  return ensureUploadFiles(opts);
}

module.exports = { ensureUploadFiles, ensureUploadFilesAsync };
