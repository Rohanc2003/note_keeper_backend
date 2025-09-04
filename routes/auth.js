import express from "express";
import { sendOTP } from "../utils/mailer.js";
import db from "../db.js";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import passport from "passport";

dotenv.config();
const router = express.Router();

/**
 * ---------- OTP LOGIN/SIGNUP ----------
 */

// SIGNUP → Request OTP
router.post("/request-otp", async (req, res) => {
  const { name, email } = req.body;
  if (!name || !email) return res.status(400).json({ error: "Name & Email required" });

  try {
    let userRes = await db.query("SELECT id FROM users WHERE email=$1", [email]);
    if (userRes.rows.length > 0) {
      return res.status(400).json({ error: "User already exists. Please login instead." });
    }

    const insertUser = await db.query(
      "INSERT INTO users (name, email) VALUES ($1, $2) RETURNING id",
      [name, email]
    );
    const user_id = insertUser.rows[0].id;

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000);

    await sendOTP(email, otp);
    await db.query("DELETE FROM otps WHERE user_id=$1", [user_id]);
    await db.query(
      "INSERT INTO otps (user_id, otp, expires_at) VALUES ($1, $2, $3)",
      [user_id, otp, expiresAt]
    );

    res.json({ message: "OTP sent successfully" });
  } catch (err) {
    console.error("Signup OTP error:", err);
    res.status(500).json({ error: err.message });
  }
});

// LOGIN → Request OTP
router.post("/login-check", async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: "Email required" });

  try {
    const userRes = await db.query("SELECT id, name FROM users WHERE email=$1", [email]);
    if (userRes.rows.length === 0) {
      return res.status(400).json({ error: "User not registered. Please sign up first." });
    }

    const user_id = userRes.rows[0].id;
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000);

    await sendOTP(email, otp);
    await db.query("DELETE FROM otps WHERE user_id=$1", [user_id]);
    await db.query(
      "INSERT INTO otps (user_id, otp, expires_at) VALUES ($1, $2, $3)",
      [user_id, otp, expiresAt]
    );

    return res.json({ message: "OTP sent successfully" });
  } catch (err) {
    console.error("Login OTP error:", err);
    res.status(500).json({ error: err.message });
  }
});

// VERIFY OTP
router.post("/verify-otp", async (req, res) => {
  const { email, otp } = req.body;
  if (!email || !otp) return res.status(400).json({ error: "Email & OTP required" });

  try {
    const userRes = await db.query("SELECT id, name, email FROM users WHERE email=$1", [email]);
    if (userRes.rows.length === 0) return res.status(400).json({ error: "User not found" });

    const user_id = userRes.rows[0].id;
    const otpRes = await db.query(
      "SELECT * FROM otps WHERE user_id=$1 AND otp=$2 AND expires_at > NOW()",
      [user_id, otp]
    );
    if (otpRes.rows.length === 0)
      return res.status(400).json({ error: "Invalid or expired OTP" });

    await db.query("DELETE FROM otps WHERE user_id=$1", [user_id]);

    const user = { id: user_id, name: userRes.rows[0].name, email: userRes.rows[0].email };
    const token = jwt.sign(user, process.env.JWT_SECRET, { expiresIn: "1h" });

    res.json({ message: "OTP verified successfully", token, user });
  } catch (err) {
    console.error("OTP verify error:", err);
    res.status(500).json({ error: err.message });
  }
});

/**
 * ---------- GOOGLE LOGIN ----------
 */
router.get(
  "/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

router.get(
  "/google/callback",
  passport.authenticate("google", { failureRedirect: "https://note-keeper-frontend-pfwx.onrender.com/login" }),
  async (req, res) => {
    try {
      const user = req.user;
      const payload = { id: user.id, name: user.name, email: user.email };
      const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: "7d" });

      // Redirect frontend with token
      res.redirect(
  `https://note-keeper-frontend-pfwx.onrender.com/?token=${token}&name=${encodeURIComponent(
    user.name
  )}&email=${encodeURIComponent(user.email)}`
);
    } catch (err) {
      console.error("Google login error:", err);
      res.redirect("https://note-keeper-frontend-pfwx.onrender.com/login?error=google");
    }
  }
);

export default router;
