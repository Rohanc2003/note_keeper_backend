// routes/notes.js
import express from "express";
import db from "../db.js";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
dotenv.config();

const router = express.Router();

// Middleware to authenticate JWT
const authenticate = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: "Unauthorized" });

  const token = authHeader.split(" ")[1];
  try {
    const user = jwt.verify(token, process.env.JWT_SECRET);
    req.user = user; // add user info to request
    next();
  } catch (err) {
    return res.status(403).json({ error: "Invalid token" });
  }
};

// ✅ Get all notes for logged-in user
router.get("/", authenticate, async (req, res) => {
  try {
    const result = await db.query(
      "SELECT id, content, created_at FROM notes WHERE user_id=$1 ORDER BY created_at DESC",
      [req.user.id]
    );
    res.json({ notes: result.rows }); // ✅ return rows only
  } catch (err) {
    console.error("Get notes error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// ✅ Add a new note
router.post("/", authenticate, async (req, res) => {
  const { content } = req.body;
  if (!content) return res.status(400).json({ error: "Content is required" });

  try {
    const result = await db.query(
      "INSERT INTO notes (user_id, content, created_at) VALUES ($1, $2, NOW()) RETURNING id, content, created_at",
      [req.user.id, content]
    );
    res.json({ note: result.rows[0] });
  } catch (err) {
    console.error("Add note error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// ✅ Delete a note
router.delete("/:id", authenticate, async (req, res) => {
  const noteId = req.params.id;
  try {
    await db.query("DELETE FROM notes WHERE id=$1 AND user_id=$2", [
      noteId,
      req.user.id,
    ]);
    res.json({ message: "Note deleted" });
  } catch (err) {
    console.error("Delete note error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

export default router;
