const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs-extra');
const jwt = require('jsonwebtoken');
const { db } = require('../database/init');

const router = express.Router();

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadsDir = path.join(__dirname, '../uploads');
    fs.ensureDirSync(uploadsDir);
    cb(null, uploadsDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({ 
  storage: storage,
  limits: {
    fileSize: 100 * 1024 * 1024 // 100MB limit
  },
  fileFilter: (req, file, cb) => {
    // Allow all file types
    cb(null, true);
  }
});

// Middleware to verify JWT token
const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'No token provided' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(401).json({ message: 'Invalid token' });
  }
};

// Upload file
router.post('/upload', verifyToken, upload.single('file'), (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ message: 'No file uploaded' });
    }

    const { filename, originalname, path: filePath, size, mimetype } = req.file;

    db.run(
      'INSERT INTO files (user_id, filename, original_name, file_path, file_size, mime_type) VALUES (?, ?, ?, ?, ?, ?)',
      [req.user.userId, filename, originalname, filePath, size, mimetype],
      function(err) {
        if (err) {
          // Clean up uploaded file if database insert fails
          fs.unlinkSync(filePath);
          return res.status(500).json({ message: 'Failed to save file metadata' });
        }

        res.json({
          message: 'File uploaded successfully',
          file: {
            id: this.lastID,
            filename: originalname,
            size: size,
            uploadedAt: new Date().toISOString()
          }
        });
      }
    );
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Get user's files
router.get('/list', verifyToken, (req, res) => {
  try {
    db.all(
      'SELECT id, original_name, file_size, mime_type, uploaded_at FROM files WHERE user_id = ? ORDER BY uploaded_at DESC',
      [req.user.userId],
      (err, files) => {
        if (err) {
          return res.status(500).json({ message: 'Database error' });
        }

        res.json({ files });
      }
    );
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Download file
router.get('/download/:fileId', verifyToken, (req, res) => {
  try {
    const { fileId } = req.params;

    db.get(
      'SELECT * FROM files WHERE id = ? AND user_id = ?',
      [fileId, req.user.userId],
      (err, file) => {
        if (err) {
          return res.status(500).json({ message: 'Database error' });
        }

        if (!file) {
          return res.status(404).json({ message: 'File not found' });
        }

        const filePath = path.join(__dirname, '../uploads', file.filename);

        if (!fs.existsSync(filePath)) {
          return res.status(404).json({ message: 'File not found on disk' });
        }

        res.download(filePath, file.original_name);
      }
    );
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Delete file
router.delete('/delete/:fileId', verifyToken, (req, res) => {
  try {
    const { fileId } = req.params;

    db.get(
      'SELECT * FROM files WHERE id = ? AND user_id = ?',
      [fileId, req.user.userId],
      (err, file) => {
        if (err) {
          return res.status(500).json({ message: 'Database error' });
        }

        if (!file) {
          return res.status(404).json({ message: 'File not found' });
        }

        const filePath = path.join(__dirname, '../uploads', file.filename);

        // Delete file from database
        db.run('DELETE FROM files WHERE id = ?', [fileId], (err) => {
          if (err) {
            return res.status(500).json({ message: 'Failed to delete file from database' });
          }

          // Delete file from disk
          if (fs.existsSync(filePath)) {
            fs.unlinkSync(filePath);
          }

          res.json({ message: 'File deleted successfully' });
        });
      }
    );
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Get file info
router.get('/info/:fileId', verifyToken, (req, res) => {
  try {
    const { fileId } = req.params;

    db.get(
      'SELECT id, original_name, file_size, mime_type, uploaded_at FROM files WHERE id = ? AND user_id = ?',
      [fileId, req.user.userId],
      (err, file) => {
        if (err) {
          return res.status(500).json({ message: 'Database error' });
        }

        if (!file) {
          return res.status(404).json({ message: 'File not found' });
        }

        res.json({ file });
      }
    );
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

module.exports = router;
