/**
 * Mix & Match: Mongoose model factory + HTTP routes.
 * Wired from index.js after CatalogProduct exists (enrichment reads catalog).
 */

function createMixMatchLookModel(mongoose) {
  if (mongoose.models.MixMatchLook) {
    return mongoose.models.MixMatchLook;
  }

  const mixMatchItemSchema = new mongoose.Schema(
    {
      productId: { type: String, required: true, index: true },
      position: { type: Number, default: 0, index: true },
      customLabel: { type: String, default: "" },
      variantId: { type: String, default: "" },
      slug: { type: String, default: "" },
      title: { type: String, default: "" },
      price: { type: String, default: "" },
      color: { type: String, default: "" },
      size: { type: String, default: "" },
      imgSrc: { type: String, default: "" },
      imgAlt: { type: String, default: "" },
    },
    { _id: false },
  );

  const mixMatchLookSchema = new mongoose.Schema(
    {
      title: { type: String, default: "" },
      headingText: { type: String, required: true, trim: true },
      // Kept for backward compatibility (older looks + existing UI mappings).
      // New looks can omit this and rely on before/after images.
      heroImageUrl: { type: String, default: "", trim: true },
      heroImageAlt: { type: String, default: "", trim: true },
      // Optional before/after comparison images (kept backward compatible with heroImageUrl)
      beforeImageUrl: { type: String, default: "", trim: true },
      afterImageUrl: { type: String, default: "", trim: true },
      isActive: { type: Boolean, default: true, index: true },
      sortOrder: { type: Number, default: 0, index: true },
      products: { type: [mixMatchItemSchema], default: [] },
    },
    { timestamps: true },
  );

  return mongoose.model("MixMatchLook", mixMatchLookSchema, "mixmatch_looks");
}

function registerMixMatchRoutes(app, deps) {
  const { MixMatchLook, CatalogProduct, mongoose, MIXMATCH_FALLBACK_LOOKS } = deps;

  function findMixMatchFallbackProductById(wantId) {
    const id = String(wantId || "").trim();
    if (!id) return null;
    for (const look of MIXMATCH_FALLBACK_LOOKS) {
      const hit = (look.products || []).find((p) => String(p.productId || "") === id);
      if (hit) return hit;
    }
    return null;
  }

  async function resolveMixMatchPlaceholderProduct(wantId) {
    const id = String(wantId || "").trim();
    if (!id) return null;
    const fromFallback = findMixMatchFallbackProductById(id);
    if (fromFallback) return fromFallback;
    try {
      const doc = await MixMatchLook.findOne({ "products.productId": id })
        .select({ products: 1 })
        .lean();
      const row = (doc?.products || []).find((p) => String(p?.productId || "") === id);
      return row || null;
    } catch {
      return null;
    }
  }

  /**
   * Use root-relative URLs (`/cdn/shop/...`) so images always load from whatever
   * host/port the user opened (localhost vs 127.0.0.1 vs :3001). Full URLs with a
   * wrong port were breaking Quick View thumbnails.
   */
  function mixMatchImageToAbsoluteUrl(raw) {
    const s = String(raw || "").trim();
    if (!s) return "https://placehold.co/800x1000/f1f5f9/64748b?text=Product";
    if (/^https?:\/\//i.test(s)) return s;
    if (s.startsWith("//")) return `https:${s}`;
    return s.startsWith("/") ? s : `/${s}`;
  }

  function mixMatchRowToSyntheticCatalogDoc(row) {
    const productId = String(row.productId || "").trim();
    const name = String(row.title || row.customLabel || "Product").trim() || "Product";
    const priceStr = String(row.price || "0");
    const pm = priceStr.match(/-?\d+(\.\d+)?/);
    const price = pm ? Number(pm[0]) : 0;
    const color = String(row.color || "").trim() || "Default";
    const size = String(row.size || "").trim() || "One size";
    const img = mixMatchImageToAbsoluteUrl(row.imgSrc);
    const baseSlug = String(row.slug || "")
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-|-$/g, "");
    const slug = baseSlug || productId.toLowerCase().replace(/[^a-z0-9]+/g, "-") || "mix-item";
    return {
      _id: productId,
      name,
      slug,
      price: Number.isFinite(price) ? Math.max(0, price) : 0,
      description: "",
      brand: "",
      categoryId: 0,
      variants: [
        {
          color,
          colorCode: "#cccccc",
          images: [img],
          // Omit `stock` — Quick View treats `stock: null` as 0 (Number(null)===0) and shows out of stock.
          sizes: [{ size }],
        },
      ],
      rating: 0,
      numReviews: 0,
      isFeatured: false,
      status: "active",
      sizeChartImage: "",
      sizeChartTitle: "",
    };
  }

  function buildMixMatchProductFromCatalog(productDoc, refItem) {
    if (!productDoc) return null;
    const variants = Array.isArray(productDoc.variants) ? productDoc.variants : [];
    const firstVariant = variants[0] || null;
    const sizes = Array.isArray(firstVariant?.sizes) ? firstVariant.sizes : [];
    const firstSize =
      sizes.find((s) => Number(s?.stock || 0) > 0) || sizes[0] || null;
    const firstImage =
      (Array.isArray(firstVariant?.images) && firstVariant.images[0]) || "";
    const color = firstVariant?.color || "";
    const size = firstSize?.size || "";
    const variantId = `${String(productDoc._id)}-${size || "v1"}`;
    const priceNum = Number(productDoc.discountPrice || productDoc.price || 0);
    return {
      productId: String(productDoc._id),
      variantId,
      slug: String(productDoc.slug || "").trim(),
      title: String(refItem?.customLabel || productDoc.name || "Product"),
      price: `₹${Number.isFinite(priceNum) ? priceNum.toFixed(2) : "0.00"}`,
      color: color || null,
      size: size || null,
      imgSrc: firstImage ? mixMatchImageToAbsoluteUrl(firstImage) : "",
      imgAlt: String(productDoc.name || "Product"),
    };
  }

  function buildMixMatchProductFromSnapshot(refItem) {
    const productId = String(refItem?.productId || "").trim();
    if (!productId) return null;
    return {
      productId,
      variantId: String(refItem?.variantId || `${productId}-v1`),
      slug: String(refItem?.slug || "").trim(),
      title: String(refItem?.customLabel || refItem?.title || "Product"),
      price: String(refItem?.price || "₹0.00"),
      color: refItem?.color || null,
      size: refItem?.size || null,
      imgSrc: mixMatchImageToAbsoluteUrl(refItem?.imgSrc),
      imgAlt: String(refItem?.imgAlt || refItem?.title || "Product"),
    };
  }

  async function enrichMixMatchLooks(lookDocs) {
    const list = Array.isArray(lookDocs) ? lookDocs : [];
    const rawIds = Array.from(
      new Set(
        list
          .flatMap((l) => (Array.isArray(l?.products) ? l.products : []))
          .map((p) => String(p?.productId || "").trim())
          .filter(Boolean),
      ),
    );
    const ids = rawIds.filter((id) => mongoose.isValidObjectId(id));
    const catalog = ids.length
      ? await CatalogProduct.find({ _id: { $in: ids }, status: { $ne: "inactive" } })
          .select({ _id: 1, name: 1, price: 1, discountPrice: 1, variants: 1, slug: 1 })
          .lean()
      : [];
    const byId = new Map(catalog.map((p) => [String(p._id), p]));

    return list.map((look) => {
      const lookId = String(look?._id || look?.id || "");
      const sortedProducts = (Array.isArray(look?.products) ? look.products : [])
        .slice()
        .sort((a, b) => Number(a?.position || 0) - Number(b?.position || 0))
        .map((item) => {
          const fromCatalog = buildMixMatchProductFromCatalog(
            byId.get(String(item.productId)),
            item,
          );
          return fromCatalog || buildMixMatchProductFromSnapshot(item);
        })
        .filter(Boolean);

      return {
        id: lookId,
        dataId: `shop_this_look_${lookId.slice(-6) || "mix"}`,
        title: look?.title || "",
        headingText: look?.headingText || look?.title || "",
        imageUrl: look?.heroImageUrl || "",
        imageAlt: look?.heroImageAlt || look?.headingText || "look image",
        beforeImageUrl: String(look?.beforeImageUrl || "").trim(),
        afterImageUrl: String(look?.afterImageUrl || "").trim(),
        isActive: Boolean(look?.isActive),
        sortOrder: Number(look?.sortOrder || 0),
        products: sortedProducts,
      };
    });
  }

  function sanitizeLookPayload(payload = {}) {
    const beforeImageUrl = String(payload.beforeImageUrl || "").trim();
    const afterImageUrl = String(payload.afterImageUrl || "").trim();
    const heroImageUrl = String(payload.heroImageUrl || "").trim() || beforeImageUrl;
    return {
      title: String(payload.title || "").trim(),
      headingText: String(payload.headingText || "").trim(),
      heroImageUrl,
      heroImageAlt: String(payload.heroImageAlt || "").trim(),
      beforeImageUrl,
      afterImageUrl,
      isActive: payload.isActive == null ? true : Boolean(payload.isActive),
      sortOrder: Number(payload.sortOrder || 0),
    };
  }

  function sanitizeLookItems(items = []) {
    return (Array.isArray(items) ? items : [])
      .map((it, idx) => ({
        productId: String(it?.productId || "").trim(),
        position: Number(it?.position ?? idx),
        customLabel: String(it?.customLabel || "").trim(),
        variantId: String(it?.variantId || "").trim(),
        slug: String(it?.slug || "").trim(),
        title: String(it?.title || "").trim(),
        price: String(it?.price || "").trim(),
        color: String(it?.color || "").trim(),
        size: String(it?.size || "").trim(),
        imgSrc: String(it?.imgSrc || "").trim(),
        imgAlt: String(it?.imgAlt || "").trim(),
      }))
      .filter((it) => it.productId);
  }

  function mapFallbackLooksToDocs() {
    return MIXMATCH_FALLBACK_LOOKS.map((look, lookIdx) => ({
      title: String(look?.headingText || `Look ${lookIdx + 1}`),
      headingText: String(look?.headingText || ""),
      heroImageUrl: String(look?.imageUrl || ""),
      heroImageAlt: String(look?.imageAlt || ""),
      beforeImageUrl: "",
      afterImageUrl: "",
      isActive: true,
      sortOrder: lookIdx,
      products: sanitizeLookItems(
        (Array.isArray(look?.products) ? look.products : []).map((p, pIdx) => ({
          productId: String(p?.productId || p?.variantId || `fallback-${lookIdx + 1}-${pIdx + 1}`),
          position: pIdx,
          customLabel: "",
          variantId: p?.variantId,
          title: p?.title,
          price: p?.price,
          color: p?.color,
          size: p?.size,
          imgSrc: p?.imgSrc,
          imgAlt: p?.imgAlt,
        })),
      ),
    }));
  }

  async function resolveCatalogOrSyntheticForProductId(productIdParam) {
    const id = String(productIdParam || "").trim();
    if (!id) return null;
    if (mongoose.isValidObjectId(id)) {
      const doc = await CatalogProduct.findOne({
        _id: id,
        status: { $ne: "inactive" },
      }).lean();
      if (doc) return doc;
      const snapOid = await resolveMixMatchPlaceholderProduct(id);
      if (snapOid) return mixMatchRowToSyntheticCatalogDoc(snapOid);
      return null;
    }
    const snap = await resolveMixMatchPlaceholderProduct(id);
    if (snap) return mixMatchRowToSyntheticCatalogDoc(snap);
    return null;
  }

  /** Root-relative / theme-relative image paths on real catalog docs → absolute for Quick View. */
  function absolutizeCatalogVariantImages(doc) {
    if (!doc || typeof doc !== "object") return doc;
    const variants = Array.isArray(doc.variants)
      ? doc.variants.map((v) => {
          if (!v || typeof v !== "object") return v;
          const images = Array.isArray(v.images)
            ? v.images.map((u) =>
                typeof u === "string" && u.trim()
                  ? mixMatchImageToAbsoluteUrl(u)
                  : u,
              )
            : v.images;
          return { ...v, images };
        })
      : doc.variants;
    const out = { ...doc, variants };
    if (typeof doc.sizeChartImage === "string" && doc.sizeChartImage.trim()) {
      out.sizeChartImage = mixMatchImageToAbsoluteUrl(doc.sizeChartImage);
    }
    return out;
  }

  function enrichPublicFallbackLooks(looks) {
    return (Array.isArray(looks) ? looks : []).map((look) => ({
      ...look,
      imageUrl: mixMatchImageToAbsoluteUrl(look.imageUrl),
      products: (Array.isArray(look.products) ? look.products : []).map((p) => ({
        ...p,
        imgSrc: mixMatchImageToAbsoluteUrl(p.imgSrc),
      })),
    }));
  }

  // ——— Public: full catalog-shaped doc for Quick drawer (variant pickers) ———
  app.get("/api/mixmatch/product/:productId", async (req, res) => {
    try {
      const productId = String(req.params.productId || "").trim();
      if (!productId) {
        return res.status(400).json({ error: "productId is required" });
      }
      const catalog = await resolveCatalogOrSyntheticForProductId(productId);
      if (!catalog) {
        return res.status(404).json({ error: "Product not found" });
      }
      return res.json({ ok: true, catalog: absolutizeCatalogVariantImages(catalog) });
    } catch (err) {
      console.error("Mix match product detail error", err);
      return res.status(500).json({ error: "Internal server error" });
    }
  });

  app.get("/api/mixmatch", async (req, res) => {
    try {
      const looks = await MixMatchLook.find({ isActive: true })
        .sort({ sortOrder: 1, createdAt: 1 })
        .lean();
      if (!looks.length) {
        return res.json([]);
      }
      const enriched = await enrichMixMatchLooks(looks);
      return res.json(enriched);
    } catch (err) {
      console.error("Error fetching mixmatch looks", err);
      return res.json([]);
    }
  });

  app.get("/api/admin/mixmatch", async (req, res) => {
    try {
      const items = await MixMatchLook.find({})
        .sort({ sortOrder: 1, createdAt: 1 })
        .lean();
      return res.json({ items });
    } catch (err) {
      console.error("Admin list mixmatch error", err);
      return res.status(500).json({ error: "Internal server error" });
    }
  });

  app.post("/api/admin/mixmatch", async (req, res) => {
    try {
      const payload = sanitizeLookPayload(req.body || {});
      if (!payload.headingText || (!payload.heroImageUrl && !payload.beforeImageUrl)) {
        return res.status(400).json({ error: "headingText and (beforeImageUrl or heroImageUrl) are required" });
      }
      const created = await MixMatchLook.create({ ...payload, products: [] });
      return res.status(201).json({ item: created.toObject() });
    } catch (err) {
      console.error("Admin create mixmatch error", err);
      return res.status(500).json({ error: "Internal server error" });
    }
  });

  app.post("/api/admin/mixmatch/seed-defaults", async (req, res) => {
    try {
      const exists = await MixMatchLook.countDocuments();
      if (exists > 0) {
        return res.status(409).json({
          error: "Mix & Match table already has data. Clear it first to seed defaults.",
        });
      }
      const docs = mapFallbackLooksToDocs();
      if (!docs.length) {
        return res.status(400).json({ error: "No fallback looks to seed" });
      }
      const inserted = await MixMatchLook.insertMany(docs);
      return res.status(201).json({ ok: true, count: inserted.length });
    } catch (err) {
      console.error("Admin seed mixmatch defaults error", err);
      return res.status(500).json({ error: "Internal server error" });
    }
  });

  app.put("/api/admin/mixmatch/:id", async (req, res) => {
    try {
      const id = String(req.params.id || "").trim();
      if (!id) return res.status(400).json({ error: "id is required" });
      const payload = sanitizeLookPayload(req.body || {});
      if (!payload.headingText || (!payload.heroImageUrl && !payload.beforeImageUrl)) {
        return res.status(400).json({ error: "headingText and (beforeImageUrl or heroImageUrl) are required" });
      }
      const item = await MixMatchLook.findByIdAndUpdate(
        id,
        { $set: payload },
        { new: true },
      ).lean();
      if (!item) return res.status(404).json({ error: "Look not found" });
      return res.json({ item });
    } catch (err) {
      console.error("Admin update mixmatch error", err);
      return res.status(500).json({ error: "Internal server error" });
    }
  });

  app.delete("/api/admin/mixmatch/:id", async (req, res) => {
    try {
      const id = String(req.params.id || "").trim();
      if (!id) return res.status(400).json({ error: "id is required" });
      const deleted = await MixMatchLook.findByIdAndDelete(id).lean();
      if (!deleted) return res.status(404).json({ error: "Look not found" });
      return res.json({ ok: true, deletedId: id });
    } catch (err) {
      console.error("Admin delete mixmatch error", err);
      return res.status(500).json({ error: "Internal server error" });
    }
  });

  app.put("/api/admin/mixmatch/reorder", async (req, res) => {
    try {
      const items = Array.isArray(req.body?.items) ? req.body.items : [];
      await Promise.all(
        items.map((row) => {
          const id = String(row?.id || "").trim();
          const sortOrder = Number(row?.sortOrder || 0);
          if (!id) return Promise.resolve();
          return MixMatchLook.findByIdAndUpdate(id, { $set: { sortOrder } });
        }),
      );
      return res.json({ ok: true });
    } catch (err) {
      console.error("Admin reorder mixmatch error", err);
      return res.status(500).json({ error: "Internal server error" });
    }
  });

  app.post("/api/admin/mixmatch/:id/items", async (req, res) => {
    try {
      const id = String(req.params.id || "").trim();
      if (!id) return res.status(400).json({ error: "id is required" });
      const items = sanitizeLookItems(req.body?.items || []);
      const look = await MixMatchLook.findByIdAndUpdate(
        id,
        { $set: { products: items } },
        { new: true },
      ).lean();
      if (!look) return res.status(404).json({ error: "Look not found" });
      return res.json({ item: look });
    } catch (err) {
      console.error("Admin upsert mixmatch items error", err);
      return res.status(500).json({ error: "Internal server error" });
    }
  });
}

module.exports = {
  createMixMatchLookModel,
  registerMixMatchRoutes,
};
