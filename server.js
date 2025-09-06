import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import session from "express-session";
import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import jwt from "jsonwebtoken";

import db from "./db.js";
import authRoutes from "./routes/auth.js";
import notesRoutes from "./routes/notes.js";

dotenv.config();
const app = express();
const port = process.env.PORT || 5000;

// Middlewares
app.use(
  cors({
    origin: [
      "https://note-keeper-frontend-pfwx.onrender.com"
    ],
    credentials: true,
  })
);
app.use(express.json());

app.use(
  session({
    secret: process.env.SESSION_SECRET || "supersecret",
    resave: false,
    saveUninitialized: false,
  })
);

app.use(passport.initialize());
app.use(passport.session());

// Serialize user into session
passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

// Google OAuth Strategy
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL, // e.g. http://localhost:5000/auth/google/callback
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        // Try to find existing user by google_id
        let userRes = await db.query("SELECT * FROM users WHERE google_id=$1", [profile.id]);

        if (userRes.rows.length === 0) {
          // If not found, check if same email exists (prevent duplicate key error)
          const email = profile.emails[0].value;
          let existingUser = await db.query("SELECT * FROM users WHERE email=$1", [email]);

          let user;
          if (existingUser.rows.length > 0) {
            // Update existing OTP user with google_id
            user = await db.query(
              "UPDATE users SET google_id=$1 WHERE email=$2 RETURNING *",
              [profile.id, email]
            );
            return done(null, user.rows[0]);
          }

          // Otherwise create new Google user
          const insertRes = await db.query(
            "INSERT INTO users (name, email, google_id) VALUES ($1, $2, $3) RETURNING *",
            [profile.displayName, email, profile.id]
          );
          return done(null, insertRes.rows[0]);
        }

        return done(null, userRes.rows[0]);
      } catch (err) {
        return done(err, null);
      }
    }
  )
);

// ========== AUTH ROUTES ==========

// Start Google login
app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

// Google callback route
app.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "https://note-keeper-frontend-pfwx.onrender.com/login"}),
  (req, res) => {
    const user = req.user;

    // Create JWT token
    const token = jwt.sign(
      { id: user.id, name: user.name, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    // Redirect to frontend with token + user info
    res.redirect(`${process.env.FRONTEND_URL}/login?token=${token}&name=${encodeURIComponent(user.name)}&email=${encodeURIComponent(user.email)}`);


  }
);

// Normal routes
app.use("/auth", authRoutes);
app.use("/notes", notesRoutes);

app.get("/", (req, res) => res.send("Server running..."));

app.listen(port, () => console.log(`🚀 Server running on http://localhost:${port}`));
