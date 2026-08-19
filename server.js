


import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import { Resend } from "resend";
import bcrypt from "bcryptjs";
import crypto from "crypto";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 10000;

app.use(cors());
app.use(express.json());

const resend = new Resend(process.env.RESEND_API_KEY);

/*
  Temporary in-memory storage.

  IMPORTANT:
  Accounts and OTPs will be lost if the Render
  server restarts. We will add a real database later.
*/
const pendingRegistrations = new Map();
const users = new Map();

function generateOtp() {
  return crypto.randomInt(100000, 1000000).toString();
}

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

async function sendOtpEmail(email, otp) {
  const { data, error } = await resend.emails.send({
    from: process.env.EMAIL_FROM,
    to: email,
    subject: "Your Vankleff Global verification code",
    text: `Your Vankleff Global verification code is ${otp}. This code expires in 10 minutes.`,
    html: `
      <div style="font-family: Arial, sans-serif;">
        <h2>Vankleff Global</h2>
        <p>Your verification code is:</p>
        <h1>${otp}</h1>
        <p>This code expires in 10 minutes.</p>
        <p>If you did not request this code, you can ignore this email.</p>
      </div>
    `
  });

  if (error) {
    console.error("RESEND ERROR:", error);
    throw new Error("Email could not be sent.");
  }

  return data;
}

/*
  Health check
*/
app.get("/", (req, res) => {
  res.json({
    success: true,
    message: "Backend API is live and running!"
  });
});

/*
  Register
*/
app.post("/api/auth/register", async (req, res) => {
  try {
    const { name, email, phone, password } = req.body;

    const normalizedEmail = normalizeEmail(email);

    if (!name || !normalizedEmail || !phone || !password) {
      return res.status(400).json({
        success: false,
        message: "Name, email, phone and password are required."
      });
    }

    if (!isValidEmail(normalizedEmail)) {
      return res.status(400).json({
        success: false,
        message: "Please provide a valid email address."
      });
    }

    if (password.length < 8) {
      return res.status(400).json({
        success: false,
        message: "Password must contain at least 8 characters."
      });
    }

    if (users.has(normalizedEmail)) {
      return res.status(409).json({
        success: false,
        message: "An account with this email already exists."
      });
    }

    const otp = generateOtp();
    const passwordHash = await bcrypt.hash(password, 12);

    pendingRegistrations.set(normalizedEmail, {
      name,
      email: normalizedEmail,
      phone,
      passwordHash,
      otp,
      expiresAt: Date.now() + 10 * 60 * 1000
    });

    await sendOtpEmail(normalizedEmail, otp);

    return res.json({
      success: true,
      message: "A verification code was sent to your email."
    });
  } catch (error) {
    console.error("REGISTER ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to send verification code."
    });
  }
});

/*
  Verify OTP
*/
app.post("/api/auth/verify-otp", async (req, res) => {
  try {
    const { email, otp } = req.body;
    const normalizedEmail = normalizeEmail(email);

    const registration = pendingRegistrations.get(normalizedEmail);

    if (!registration) {
      return res.status(400).json({
        success: false,
        message: "No pending registration was found."
      });
    }

    if (Date.now() > registration.expiresAt) {
      pendingRegistrations.delete(normalizedEmail);

      return res.status(400).json({
        success: false,
        message: "This verification code has expired."
      });
    }

    if (String(otp).trim() !== registration.otp) {
      return res.status(400).json({
        success: false,
        message: "Invalid verification code."
      });
    }

    users.set(normalizedEmail, {
      name: registration.name,
      email: registration.email,
      phone: registration.phone,
      passwordHash: registration.passwordHash,
      createdAt: new Date().toISOString()
    });

    pendingRegistrations.delete(normalizedEmail);

    return res.json({
      success: true,
      message: "Account verified and created successfully."
    });
  } catch (error) {
    console.error("VERIFY OTP ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to verify the code."
    });
  }
});

/*
  Resend OTP
*/
app.post("/api/auth/resend-otp", async (req, res) => {
  try {
    const { email } = req.body;
    const normalizedEmail = normalizeEmail(email);

    const registration = pendingRegistrations.get(normalizedEmail);

    if (!registration) {
      return res.status(400).json({
        success: false,
        message: "No pending registration was found."
      });
    }

    const otp = generateOtp();

    registration.otp = otp;
    registration.expiresAt = Date.now() + 10 * 60 * 1000;

    pendingRegistrations.set(normalizedEmail, registration);

    await sendOtpEmail(normalizedEmail, otp);

    return res.json({
      success: true,
      message: "A new verification code was sent to your email."
    });
  } catch (error) {
    console.error("RESEND OTP ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to resend verification code."
    });
  }
});

/*
  Login
*/
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const normalizedEmail = normalizeEmail(email);

    const user = users.get(normalizedEmail);

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Invalid email or password."
      });
    }

    const passwordMatches = await bcrypt.compare(
      password,
      user.passwordHash
    );

    if (!passwordMatches) {
      return res.status(401).json({
        success: false,
        message: "Invalid email or password."
      });
    }

    return res.json({
      success: true,
      message: "Login successful.",
      user: {
        name: user.name,
        email: user.email
      }
    });
  } catch (error) {
    console.error("LOGIN ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to complete login."
    });
  }
});

app.listen(PORT, () => {
  console.log(`Vankleff backend running on port ${PORT}`);
});
