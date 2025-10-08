const mongoose = require('mongoose');
const { GridFSBucket } = mongoose.mongo;
const { Readable } = require('stream');

let bucket;

function getBucket() {
  const db = mongoose.connection.db;
  if (!db) throw new Error('MongoDB not connected');
  if (!bucket) {
    bucket = new GridFSBucket(db, { bucketName: 'images' });
  }
  return bucket;
}

async function uploadBuffer(buffer, filename, contentType) {
  const b = getBucket();
  return new Promise((resolve, reject) => {
    const stream = Readable.from(buffer);
    const uploadStream = b.openUploadStream(filename, { contentType });
    stream.pipe(uploadStream)
      .on('error', reject)
      .on('finish', () => resolve(uploadStream.id.toString()));
  });
}

function createImageRouter() {
  const express = require('express');
  const router = express.Router();

  // GET /images/:id -> streams the image from GridFS
  router.get('/:id', async (req, res) => {
    try {
      const { id } = req.params;
      const b = getBucket();
      // Try to find file metadata
      const files = await b.find({ _id: new mongoose.Types.ObjectId(id) }).toArray();
      if (!files || files.length === 0) {
        return res.status(404).json({ error: 'Image not found' });
      }
      const file = files[0];
      if (file.contentType) res.set('Content-Type', file.contentType);
      res.set('Cache-Control', 'public, max-age=31536000, immutable');
      b.openDownloadStream(file._id)
        .on('error', (err) => {
          console.error('GridFS read error:', err);
          res.status(500).end();
        })
        .pipe(res);
    } catch (err) {
      // Invalid ObjectId or other errors
      return res.status(400).json({ error: 'Invalid image id' });
    }
  });

  return router;
}

module.exports = { uploadBuffer, createImageRouter };
