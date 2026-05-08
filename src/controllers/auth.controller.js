import userModel from "../models/user.model.js";
import { createHash } from "crypto";
import jwt from "jsonwebtoken";
import config from "../config/config.js";

export async function register(req, res) {
  try {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({
        message: `All fields are required!`,
      });
    }

    const isAlreadyRegistered = await userModel.findOne({
      $or: [{ email }, { username }],
    });

    if (isAlreadyRegistered) {
      return res.status(409).json({
        message: "Username or email already exists.",
      });
    }

    const hashedPassword = createHash("sha256").update(password).digest("hex");

    const user = await userModel.create({
      username,
      email,
      password: hashedPassword,
    });

    const accessToken = jwt.sign(
      {
        id: user._id,
      },
      config.JWT_SECRET,
      { expiresIn: "15m" },
    );

    const refreshToken = jwt.sign(
      {
        id: user._id,
      },
      config.JWT_SECRET,
      { expiresIn: "7d" },
    );

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: "strict",
      maxAge: 1000 * 60 * 60 * 24 * 7,
    });

    return res.status(201).json({
      message: "User registered successfully!",
      user: { username: user.username, email: user.email },
      accessToken,
    });
  } catch (error) {
    console.error("Registration error:", error);
    return res.status(500).json({
      message: "Internal server error.",
    });
  }
}

export async function getMe(req, res) {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({
      message: "Token not found!",
    });
  }

  const decoded = jwt.verify(token, config.JWT_SECRET);

  const user = await userModel.findById(decoded.id);

  return res.status(200).json({
    message: "User fetched successfully!",
    user: {
      username: user.username,
      email: user.email,
    },
  });
}

export async function refreshToken(req, res) {
  const refreshToken = req.cookies.refreshToken;
  if (!refreshToken) {
    return res.status(401).json({ message: "Refresh token not found." });
  }

  const decoded = jwt.verify(refreshToken, config.JWT_SECRET);

  const accessToken = jwt.sign({ id: decoded.id }, config.JWT_SECRET, {
    expiresIn: "15m",
  });

  const newRefreshToken = jwt.sign({ id: decoded.id }, config.JWT_SECRET, {
    expiresIn: "7d",
  });

  res.cookie("refreshToken", newRefreshToken, {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    maxAge: 1000 * 60 * 60 * 24 * 7,
  });

  return res
    .status(200)
    .json({ message: "Access token refreshed successfully!", accessToken });
}
