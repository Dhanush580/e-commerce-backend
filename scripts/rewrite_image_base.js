/*
  Rewrite product image URLs from an old base to a new base.
  - Safe and idempotent: only rewrites when a URL starts with OLD_IMAGE_BASE
    (or when OLD_IMAGE_BASE is omitted, rewrites any '/uploads/' path to NEW_IMAGE_BASE/uploads/...)
  - Does not touch products with non-matching URLs

  Required env:
    MONGODB_URI=mongodb+srv://... (or mongodb://...)
    NEW_IMAGE_BASE=http://host:port  (no trailing slash)
  Optional env:
    OLD_IMAGE_BASE=http://localhost:5000  (no trailing slash)

  Run:
    node scripts/rewrite_image_base.js
*/

require('dotenv').config();
const mongoose = require('mongoose');
const Product = require('../models/Product');

(async function main() {
  const mongoUri = process.env.MONGODB_URI;
  const NEW_BASE = (process.env.NEW_IMAGE_BASE || '').replace(/\/$/, '');
  const OLD_BASE_RAW = process.env.OLD_IMAGE_BASE ? process.env.OLD_IMAGE_BASE.replace(/\/$/, '') : '';

  if (!mongoUri) {
    console.error('Missing MONGODB_URI');
    process.exit(1);
  }
  if (!NEW_BASE) {
    console.error('Missing NEW_IMAGE_BASE');
    process.exit(1);
  }

  await mongoose.connect(mongoUri);
  console.log('[DB] Connected');

  const products = await Product.find({}).select('_id images');
  let changed = 0;

  for (const p of products) {
    if (!Array.isArray(p.images) || p.images.length === 0) continue;

    const updated = p.images.map((url) => {
      if (typeof url !== 'string') return url;

      if (OLD_BASE_RAW) {
        // Rewrite only if it explicitly starts with OLD_IMAGE_BASE
        if (url.startsWith(OLD_BASE_RAW + '/uploads/')) {
          return url.replace(OLD_BASE_RAW, NEW_BASE);
        }
        return url;
      } else {
        // No OLD base provided. If URL is a relative or absolute path to /uploads,
        // convert to NEW_BASE/uploads.
        try {
          // Absolute URL? Check its path
          const u = new URL(url);
          if (u.pathname.startsWith('/uploads/')) {
            return NEW_BASE + u.pathname;
          }
          return url;
        } catch {
          // Not a valid absolute URL. Treat as path.
          if (url.startsWith('/uploads/')) {
            return NEW_BASE + url;
          }
          // Already a different absolute URL (e.g., external CDN) or data URL; leave as is.
          return url;
        }
      }
    });

    // Save only if changed
    const changedThis = updated.some((u, i) => u !== p.images[i]);
    if (changedThis) {
      p.images = updated;
      await p.save();
      changed += 1;
      console.log(`Updated product ${p._id}`);
    }
  }

  console.log(`Done. Products updated: ${changed}`);
  await mongoose.disconnect();
  process.exit(0);
})().catch(async (err) => {
  console.error('Migration failed:', err);
  try { await mongoose.disconnect(); } catch {}
  process.exit(1);
});
