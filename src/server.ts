import express from "express";
import dotenv from "dotenv";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { z } from "zod";
import cookieParser from "cookie-parser";
import { prisma } from "./prisma";
import path from "path";

dotenv.config({ path: path.resolve("/var/www/anti-scam-api/.env") });

const app = express();

/**
 * Если ты под nginx/https прокси, это важно для secure cookies
 */
app.set("trust proxy", 1);

app.use(express.json());
app.use(cookieParser());

/**
 * ENV
 */
const ACCESS_TTL_MIN = Number(process.env.ACCESS_TTL_MIN ?? 15);
const REFRESH_TTL_DAYS = Number(process.env.REFRESH_TTL_DAYS ?? 7);
const BCRYPT_ROUNDS = Number(process.env.BCRYPT_ROUNDS ?? 10);

const ACCESS_SECRET = process.env.JWT_ACCESS_SECRET!;
const REFRESH_SECRET = process.env.JWT_REFRESH_SECRET!;

if (!ACCESS_SECRET || !REFRESH_SECRET) {
  throw new Error("JWT secrets are missing in .env");
}

/**
 * Cookie settings
 * - sameSite: "lax" для localhost
 * - sameSite: "none" + secure: true для продакшена если фронт и бэк на разных доменах
 */
const isProd = process.env.NODE_ENV === "production";

const cookieAccessName = process.env.COOKIE_ACCESS_NAME ?? "user_token";
const cookieRefreshName = process.env.COOKIE_REFRESH_NAME ?? "refresh_token";

const cookieBase = {
  httpOnly: true,
  secure: isProd,
  sameSite: (isProd ? "none" : "lax") as "none" | "lax",
  path: "/",
  // domain: "gfta-api.online", // можно включить при желании. обычно не нужно.
};

function setAuthCookies(
  res: express.Response,
  accessToken: string,
  refreshToken: string,
) {
  res.cookie(cookieAccessName, accessToken, {
    ...cookieBase,
    maxAge: ACCESS_TTL_MIN * 60 * 1000,
  });

  res.cookie(cookieRefreshName, refreshToken, {
    ...cookieBase,
    maxAge: REFRESH_TTL_DAYS * 24 * 60 * 60 * 1000,
  });
}

function clearAuthCookies(res: express.Response) {
  res.cookie(cookieAccessName, "", { ...cookieBase, maxAge: 0 });
  res.cookie(cookieRefreshName, "", { ...cookieBase, maxAge: 0 });
}

/**
 * Schemas
 */
const AuthSchema = z.object({
  email: z
    .string()
    .email()
    .max(254)
    .transform((v) => v.trim().toLowerCase()),
  password: z.string().min(8).max(72),
});

const ChangePasswordSchema = z
  .object({
    oldPassword: z.string().min(8).max(72),
    newPassword: z.string().min(8).max(72),
    revokeAllSessions: z.boolean().optional(),
  })
  .refine((d) => d.oldPassword !== d.newPassword, {
    message: "New password must be different from old password",
    path: ["newPassword"],
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

function getUserIdFromAccessCookie(req: express.Request): string | null {
  const accessToken = req.cookies?.[cookieAccessName];
  if (!accessToken || typeof accessToken !== "string") return null;

  try {
    const payload: any = jwt.verify(accessToken, ACCESS_SECRET);
    const userId = payload?.sub;
    return typeof userId === "string" ? userId : null;
  } catch {
    return null;
  }
}

/**
 * ✅ IP / UA helpers (added)
 */
function getClientIp(req: express.Request) {
  const cf = req.headers["cf-connecting-ip"];
  if (typeof cf === "string" && cf.trim()) return cf.trim();

  const xff = req.headers["x-forwarded-for"];
  if (typeof xff === "string" && xff.trim()) return xff.split(",")[0]!.trim();

  const ra = req.socket?.remoteAddress;
  return typeof ra === "string" ? ra : "unknown";
}

type AuthedRequest = express.Request & { userId?: string };

function requireAuth(
  req: AuthedRequest,
  res: express.Response,
  next: express.NextFunction,
) {
  const userId = getUserIdFromAccessCookie(req);
  if (!userId) return res.status(401).json({ error: "Unauthorized" });
  req.userId = userId;
  next();
}

async function requireAdmin(
  req: AuthedRequest,
  res: express.Response,
  next: express.NextFunction,
) {
  const userId = req.userId;
  if (!userId) return res.status(401).json({ error: "Unauthorized" });

  const u = await prisma.user.findUnique({
    where: { id: userId },
    select: { role: true, status: true },
  });

  if (!u) return res.status(401).json({ error: "Unauthorized" });
  if (u.status === "BLOCKED")
    return res.status(403).json({ error: "Forbidden" });
  if (u.role !== "ADMIN") return res.status(403).json({ error: "Forbidden" });

  next();
}

/**
 * ROUTES
 */

app.post("/auth/signup", async (req, res) => {
  const parsed = AuthSchema.safeParse(req.body);
  if (!parsed.success) {
    return res
      .status(400)
      .json({ error: "Invalid input", details: parsed.error.flatten() });
  }

  const { email, password } = parsed.data;

  const exists = await prisma.user.findUnique({ where: { email } });
  if (exists) return res.status(409).json({ error: "Email already in use" });

  const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);

  // added
  const ip = getClientIp(req);
  const userAgent =
    typeof req.headers["user-agent"] === "string"
      ? req.headers["user-agent"]
      : undefined;

  // ✅ создаём PENDING пользователя и заявку с IP (added)
  const user = await prisma.user.create({
    data: {
      email,
      passwordHash,
      role: "USER",
      status: "PENDING",
      registrationRequests: {
        create: {
          ip,
          userAgent,
          status: "PENDING",
        },
      },
    },
  });

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

  setAuthCookies(res, accessToken, refreshToken);

  return res.status(201).json({
    user: { id: user.id, email: user.email },
  });
});

app.post("/auth/login", async (req, res) => {
  const parsed = AuthSchema.safeParse(req.body);
  if (!parsed.success) {
    return res
      .status(400)
      .json({ error: "Invalid input", details: parsed.error.flatten() });
  }

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

  setAuthCookies(res, accessToken, refreshToken);

  return res.json({
    user: { id: user.id, email: user.email },
  });
});

app.post("/auth/refresh", async (req, res) => {
  const refreshToken = req.cookies?.[cookieRefreshName];
  if (!refreshToken || typeof refreshToken !== "string") {
    clearAuthCookies(res);
    return res.status(401).json({ error: "No refresh token" });
  }

  let payload: any;
  try {
    payload = jwt.verify(refreshToken, REFRESH_SECRET);
  } catch {
    clearAuthCookies(res);
    return res.status(401).json({ error: "Invalid refresh token" });
  }

  const sessionId = payload.sid as string;
  const userId = payload.sub as string;

  const session = await prisma.session.findUnique({ where: { id: sessionId } });
  if (!session || session.userId !== userId) {
    clearAuthCookies(res);
    return res.status(401).json({ error: "Session not found" });
  }

  if (session.expiresAt.getTime() < Date.now()) {
    clearAuthCookies(res);
    return res.status(401).json({ error: "Session expired" });
  }

  const matches = await bcrypt.compare(refreshToken, session.refreshHash);
  if (!matches) {
    clearAuthCookies(res);
    return res.status(401).json({ error: "Invalid refresh token" });
  }

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

  setAuthCookies(res, newAccessToken, newRefreshToken);

  return res.json({ ok: true });
});

app.post("/auth/logout", async (req, res) => {
  const refreshToken = req.cookies?.[cookieRefreshName];

  if (refreshToken && typeof refreshToken === "string") {
    try {
      const payload: any = jwt.verify(refreshToken, REFRESH_SECRET);
      const sessionId = payload.sid as string;
      await prisma.session.delete({ where: { id: sessionId } }).catch(() => {});
    } catch {
      // одинаковый ответ всегда
    }
  }

  clearAuthCookies(res);
  return res.json({ ok: true });
});

app.get("/auth/me", async (req, res) => {
  const userId = getUserIdFromAccessCookie(req);
  if (!userId) return res.status(401).json({ error: "Unauthorized" });

  // updated: role/status added
  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: { id: true, email: true, role: true, status: true },
  });
  if (!user) return res.status(401).json({ error: "Unauthorized" });

  return res.json({ user });
});

/**
 * ✅ Смена пароля: старый + новый.
 * Требует, чтобы access cookie была валидной (то есть юзер залогинен).
 */
app.post("/auth/change-password", async (req, res) => {
  const userId = getUserIdFromAccessCookie(req);
  if (!userId) {
    clearAuthCookies(res);
    return res.status(401).json({ error: "Unauthorized" });
  }

  const parsed = ChangePasswordSchema.safeParse(req.body);
  if (!parsed.success) {
    return res
      .status(400)
      .json({ error: "Invalid input", details: parsed.error.flatten() });
  }

  const { oldPassword, newPassword, revokeAllSessions } = parsed.data;

  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: { id: true, email: true, passwordHash: true },
  });

  if (!user) {
    clearAuthCookies(res);
    return res.status(401).json({ error: "Unauthorized" });
  }

  const ok = await bcrypt.compare(oldPassword, user.passwordHash);
  if (!ok) return res.status(401).json({ error: "Old password is incorrect" });

  const newHash = await bcrypt.hash(newPassword, BCRYPT_ROUNDS);

  await prisma.user.update({
    where: { id: user.id },
    data: { passwordHash: newHash },
  });

  if (revokeAllSessions) {
    await prisma.session.deleteMany({ where: { userId: user.id } });
    clearAuthCookies(res);
    return res.json({ ok: true, revoked: true });
  }

  return res.json({ ok: true });
});

const ChangePasswordByEmailSchema = z
  .object({
    email: z
      .string()
      .email()
      .max(254)
      .transform((v) => v.trim().toLowerCase()),
    oldPassword: z.string().min(8).max(72),
    newPassword: z.string().min(8).max(72),
  })
  .refine((d) => d.oldPassword !== d.newPassword, {
    message: "New password must be different from old password",
    path: ["newPassword"],
  });

app.post("/auth/change-password-by-email", async (req, res) => {
  const parsed = ChangePasswordByEmailSchema.safeParse(req.body);
  if (!parsed.success) {
    return res
      .status(400)
      .json({ error: "Invalid input", details: parsed.error.flatten() });
  }

  const { email, oldPassword, newPassword } = parsed.data;

  const user = await prisma.user.findUnique({
    where: { email },
    select: { id: true, email: true, passwordHash: true },
  });

  // одинаковый ответ, чтобы не палить существование email (опционально, но правильно)
  if (!user) return res.status(401).json({ error: "Invalid credentials" });

  const ok = await bcrypt.compare(oldPassword, user.passwordHash);
  if (!ok) return res.status(401).json({ error: "Invalid credentials" });

  const newHash = await bcrypt.hash(newPassword, BCRYPT_ROUNDS);

  await prisma.user.update({
    where: { id: user.id },
    data: { passwordHash: newHash },
  });

  return res.json({ ok: true });
});

/**
 * ============================
 * ✅ ADMIN ENDPOINTS (added)
 * ============================
 */

/**
 * GET /admin/registration-requests?status=PENDING|APPROVED|REJECTED&search=...
 */
app.get(
  "/admin/registration-requests",
  requireAuth,
  requireAdmin,
  async (req, res) => {
    const status = String(req.query.status ?? "PENDING").toUpperCase();
    const search = String(req.query.search ?? "").trim();

    const safeStatus = ["PENDING", "APPROVED", "REJECTED"].includes(status)
      ? (status as any)
      : ("PENDING" as any);

    const items = await prisma.registrationRequest.findMany({
      where: {
        status: safeStatus,
        ...(search
          ? {
              OR: [
                { ip: { contains: search, mode: "insensitive" } },
                { userAgent: { contains: search, mode: "insensitive" } },
                { user: { email: { contains: search, mode: "insensitive" } } },
              ],
            }
          : {}),
      },
      orderBy: { createdAt: "desc" },
      take: 200,
      include: {
        user: {
          select: {
            id: true,
            email: true,
            role: true,
            status: true,
            createdAt: true,
          },
        },
      },
    });

    return res.json({ items });
  },
);

/**
 * POST /admin/registration-requests/:id/approve
 * approve -> request APPROVED + user ACTIVE
 */
app.post(
  "/admin/registration-requests/:id/approve",
  requireAuth,
  requireAdmin,
  async (req: AuthedRequest, res) => {
    const id = req.params.id;

    const rr = await prisma.registrationRequest.findUnique({ where: { id } });
    if (!rr) return res.status(404).json({ error: "Not found" });

    if (rr.status !== "PENDING") return res.json({ ok: true, already: true });

    await prisma.$transaction([
      prisma.registrationRequest.update({
        where: { id },
        data: {
          status: "APPROVED" as any,
          reviewedBy: req.userId!,
          reviewedAt: new Date(),
        },
      }),
      prisma.user.update({
        where: { id: rr.userId },
        data: { status: "ACTIVE" as any },
      }),
    ]);

    return res.json({ ok: true });
  },
);

/**
 * POST /admin/registration-requests/:id/reject
 * reject -> request REJECTED + user BLOCKED
 */
app.post(
  "/admin/registration-requests/:id/reject",
  requireAuth,
  requireAdmin,
  async (req: AuthedRequest, res) => {
    const id = req.params.id;

    const rr = await prisma.registrationRequest.findUnique({ where: { id } });
    if (!rr) return res.status(404).json({ error: "Not found" });

    if (rr.status !== "PENDING") return res.json({ ok: true, already: true });

    await prisma.$transaction([
      prisma.registrationRequest.update({
        where: { id },
        data: {
          status: "REJECTED" as any,
          reviewedBy: req.userId!,
          reviewedAt: new Date(),
        },
      }),
      prisma.user.update({
        where: { id: rr.userId },
        data: { status: "BLOCKED" as any },
      }),
    ]);

    return res.json({ ok: true });
  },
);

/**
 * GET /admin/users?status=ACTIVE|PENDING|BLOCKED&search=...
 */
app.get("/admin/users", requireAuth, requireAdmin, async (req, res) => {
  const search = String(req.query.search ?? "").trim();
  const status = String(req.query.status ?? "").toUpperCase();

  const where: any = {};

  if (["ACTIVE", "PENDING", "BLOCKED"].includes(status)) {
    where.status = status;
  }

  if (search) {
    where.OR = [{ email: { contains: search, mode: "insensitive" } }];
  }

  const items = await prisma.user.findMany({
    where,
    orderBy: { createdAt: "desc" },
    take: 300,
    select: {
      id: true,
      email: true,
      role: true,
      status: true,
      createdAt: true,
      registrationRequests: {
        orderBy: { createdAt: "desc" },
        take: 1,
        select: { ip: true },
      },
    },
  });

  const mapped = items.map((u) => ({
    id: u.id,
    email: u.email,
    role: u.role,
    status: u.status,
    createdAt: u.createdAt,
    ip: u.registrationRequests[0]?.ip ?? "unknown",
  }));

  return res.json({ items: mapped });
});

const AdminUpdateUserSchema = z.object({
  role: z.enum(["USER", "ADMIN"]).optional(),
  status: z.enum(["ACTIVE", "PENDING", "BLOCKED"]).optional(),
});

/**
 * PATCH /admin/users/:id
 * body: { role?, status? }
 */
app.patch(
  "/admin/users/:id",
  requireAuth,
  requireAdmin,
  async (req: AuthedRequest, res) => {
    const id = req.params.id;

    const parsed = AdminUpdateUserSchema.safeParse(req.body);
    if (!parsed.success) {
      return res
        .status(400)
        .json({ error: "Invalid input", details: parsed.error.flatten() });
    }

    const meId = req.userId!;

    // защита от гениальных решений: не даём админу снять с себя ADMIN
    if (id === meId && parsed.data.role === "USER") {
      return res
        .status(400)
        .json({ error: "You cannot remove admin role from yourself" });
    }

    const updated = await prisma.user.update({
      where: { id },
      data: parsed.data as any,
      select: { id: true, email: true, role: true, status: true },
    });

    return res.json({ ok: true, user: updated });
  },
);

const PORT = Number(process.env.PORT || 4000);

app.listen(PORT, () => {
  console.log(`Auth API running on http://localhost:${PORT}`);
});
