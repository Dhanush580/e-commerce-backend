require('dotenv').config();
const path = require('path');
const fs = require('fs/promises');
const mongoose = require('mongoose');
const Product = require('../models/Product');
const { uploadBuffer } = require('../utils/gridfs');

async function fileExists(p) {
  try { await fs.access(p); return true; } catch { return false; }
}

(async function main() {
  const mongoUri = process.env.MONGODB_URI;
  if (!mongoUri) {
    console.error('Missing MONGODB_URI');
    process.exit(1);
  }
  await mongoose.connect(mongoUri);
  console.log('[DB] Connected');

  const baseUploads = path.join(__dirname, '..', 'uploads');
  const products = await Product.find({ images: { $exists: true, $ne: [] } }).select('_id images');

  let updatedCount = 0;
  for (const p of products) {
    const newImages = [];
    let changed = false;
    for (let u of p.images) {
      if (typeof u !== 'string') { newImages.push(u); continue; }
      // If absolute URL, try to extract pathname
      try {
        const parsed = new URL(u);
        if (parsed.pathname && parsed.pathname.startsWith('/uploads/')) {
          u = parsed.pathname;
        }
      } catch { /* not an absolute URL */ }

      if (u.startsWith('/uploads/')) {
        const rel = u.replace('/uploads/', '');
        const localPath = path.join(baseUploads, rel);
        if (await fileExists(localPath)) {
          const buf = await fs.readFile(localPath);
          const ext = path.extname(rel).toLowerCase();
          const ct = ext === '.png' ? 'image/png' : ext === '.webp' ? 'image/webp' : ext === '.jpg' || ext === '.jpeg' ? 'image/jpeg' : 'application/octet-stream';
          const id = await uploadBuffer(buf, rel, ct);
          newImages.push(`/images/${id}`);
          changed = true;
        } else {
          // Keep original if file missing
          newImages.push(u);
          console.warn(`Missing local file for ${u} (product ${p._id})`);
        }
      } else {
        newImages.push(u);
      }
    }
    if (changed) {
      p.images = newImages;
      await p.save();
      updatedCount++;
      console.log(`Updated product ${p._id}`);
    }
  }

  console.log(`Done. Products updated: ${updatedCount}`);
  await mongoose.disconnect();
  process.exit(0);
})().catch(async (err) => {
  console.error('Migration failed:', err);
  try { await mongoose.disconnect(); } catch {}
  process.exit(1);
});
