import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { z } from "zod";
import { prisma } from "./prisma";

dotenv.config();
const app = express();

app.use(cors());
app.use(express.json());

const ACCESS_TTL_MIN = Number(process.env.ACCESS_TTL_MIN ?? 15);
const REFRESH_TTL_DAYS = Number(process.env.REFRESH_TTL_DAYS ?? 7);
const BCRYPT_ROUNDS = Number(process.env.BCRYPT_ROUNDS ?? 10);

const ACCESS_SECRET = process.env.JWT_ACCESS_SECRET!;
const REFRESH_SECRET = process.env.JWT_REFRESH_SECRET!;

if (!ACCESS_SECRET || !REFRESH_SECRET) {
  throw new Error("JWT secrets are missing in .env");
}

const AuthSchema = z.object({
  email: z
    .string()
    .email()
    .max(254)
    .transform((v) => v.trim().toLowerCase()),
  password: z.string().min(8).max(72),
});

function signAccessToken(userId: string) {
  return jwt.sign({ sub: userId }, ACCESS_SECRET, {
    expiresIn: `${ACCESS_TTL_MIN}m`,
  });
}

function signRefreshToken(sessionId: string, userId: string) {
  return jwt.sign({ sid: sessionId, sub: userId }, REFRESH_SECRET, {
    expiresIn: `${REFRESH_TTL_DAYS}d`,
  });
}

function addDays(date: Date, days: number) {
  const d = new Date(date);
  d.setDate(d.getDate() + days);
  return d;
}

app.post("/auth/signup", async (req, res) => {
  const parsed = AuthSchema.safeParse(req.body);
  if (!parsed.success)
    return res
      .status(400)
      .json({ error: "Invalid input", details: parsed.error.flatten() });

  const { email, password } = parsed.data;

  const exists = await prisma.user.findUnique({ where: { email } });
  if (exists) return res.status(409).json({ error: "Email already in use" });

  const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);
  const user = await prisma.user.create({ data: { email, passwordHash } });

  // создаем сессию + refresh
  const session = await prisma.session.create({
    data: {
      userId: user.id,
      refreshHash: "temp", // заменим ниже
      expiresAt: addDays(new Date(), REFRESH_TTL_DAYS),
    },
  });

  const refreshToken = signRefreshToken(session.id, user.id);
  const refreshHash = await bcrypt.hash(refreshToken, BCRYPT_ROUNDS);

  await prisma.session.update({
    where: { id: session.id },
    data: { refreshHash },
  });

  const accessToken = signAccessToken(user.id);

  return res.status(201).json({
    user: { id: user.id, email: user.email },
    accessToken,
    refreshToken,
  });
});

app.post("/auth/login", async (req, res) => {
  const parsed = AuthSchema.safeParse(req.body);
  if (!parsed.success)
    return res
      .status(400)
      .json({ error: "Invalid input", details: parsed.error.flatten() });

  const { email, password } = parsed.data;

  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) return res.status(401).json({ error: "Invalid credentials" });

  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(401).json({ error: "Invalid credentials" });

  const session = await prisma.session.create({
    data: {
      userId: user.id,
      refreshHash: "temp",
      expiresAt: addDays(new Date(), REFRESH_TTL_DAYS),
    },
  });

  const refreshToken = signRefreshToken(session.id, user.id);
  const refreshHash = await bcrypt.hash(refreshToken, BCRYPT_ROUNDS);

  await prisma.session.update({
    where: { id: session.id },
    data: { refreshHash },
  });

  const accessToken = signAccessToken(user.id);

  return res.json({
    user: { id: user.id, email: user.email },
    accessToken,
    refreshToken,
  });
});

const RefreshSchema = z.object({
  refreshToken: z.string().min(10),
});

app.post("/auth/refresh", async (req, res) => {
  const parsed = RefreshSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "Invalid input" });

  const { refreshToken } = parsed.data;

  let payload: any;
  try {
    payload = jwt.verify(refreshToken, REFRESH_SECRET);
  } catch {
    return res.status(401).json({ error: "Invalid refresh token" });
  }

  const sessionId = payload.sid as string;
  const userId = payload.sub as string;

  const session = await prisma.session.findUnique({ where: { id: sessionId } });
  if (!session || session.userId !== userId)
    return res.status(401).json({ error: "Session not found" });
  if (session.expiresAt.getTime() < Date.now())
    return res.status(401).json({ error: "Session expired" });

  const matches = await bcrypt.compare(refreshToken, session.refreshHash);
  if (!matches) return res.status(401).json({ error: "Invalid refresh token" });

  // ротация refresh (чтобы украденный токен быстро умер)
  const newRefreshToken = signRefreshToken(session.id, userId);
  const newRefreshHash = await bcrypt.hash(newRefreshToken, BCRYPT_ROUNDS);

  await prisma.session.update({
    where: { id: session.id },
    data: {
      refreshHash: newRefreshHash,
      expiresAt: addDays(new Date(), REFRESH_TTL_DAYS),
    },
  });

  const newAccessToken = signAccessToken(userId);

  return res.json({
    accessToken: newAccessToken,
    refreshToken: newRefreshToken,
  });
});

app.post("/auth/logout", async (req, res) => {
  const parsed = RefreshSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "Invalid input" });

  const { refreshToken } = parsed.data;

  try {
    const payload: any = jwt.verify(refreshToken, REFRESH_SECRET);
    const sessionId = payload.sid as string;
    await prisma.session.delete({ where: { id: sessionId } }).catch(() => {});
  } catch {
    // даже если токен мусор, отвечаем одинаково
  }

  return res.json({ ok: true });
});

const PORT = Number(process.env.PORT || 4000);

app.listen(Number(PORT), () => {
  console.log(
    `Auth API running on http://localhost:${process.env.PORT ?? 4000}`
  );
});
