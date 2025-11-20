import { Request, Response } from "express";
import { prisma } from "../../../core/db/client";
import { hashPassword } from "../../../core/utils/bcrypt";
import { createUserSchema, updateUserSchema } from "../dto/auth.dto";

// ─── CREATE USER (Sysadmin) ─────────────────
export const createUserBySysadmin = async (req: Request, res: Response) => {
  const parse = createUserSchema.safeParse(req.body);
  if (!parse.success) return res.status(400).json({ error: "Validation failed", details: parse.error.format() });

  const { email, password, role } = parse.data;
  const hashed = await hashPassword(password);

  try {
    let user;
    if (role === "CLIENT") {
      user = await prisma.client.create({ data: { email, password: hashed } });
    } else {
      user = await prisma.admin.create({ data: { email, password: hashed, role } });
    }
    return res.status(201).json({ message: `${role} created`, user });
  } catch (err: any) {
    if (err.code === "P2002") return res.status(400).json({ error: "Email already exists" });
    return res.status(500).json({ error: "Failed to create user" });
  }
};

// ─── READ ALL USERS ─────────────────
export const listUsers = async (_req: Request, res: Response) => {
  try {
    const clients = await prisma.client.findMany({ select: { id: true, email: true, createdAt: true } });
    const admins = await prisma.admin.findMany({ select: { id: true, email: true, role: true, createdAt: true } });
    return res.json({ clients, admins });
  } catch (err) {
    return res.status(500).json({ error: "Failed to fetch users" });
  }
};

// ─── READ USER BY ID ─────────────────
export const getUserById = async (req: Request, res: Response) => {
  const { id } = req.params;
  try {
    let user = await prisma.client.findUnique({ where: { id } });
    if (!user) user = await prisma.admin.findUnique({ where: { id } });
    if (!user) return res.status(404).json({ error: "User not found" });
    return res.json(user);
  } catch (err) {
    return res.status(500).json({ error: "Failed to fetch user" });
  }
};

// ─── UPDATE USER ─────────────────
export const updateUserBySysadmin = async (req: Request, res: Response) => {
  const { id } = req.params;
  const parse = updateUserSchema.safeParse(req.body);
  if (!parse.success) return res.status(400).json({ error: "Validation failed", details: parse.error.format() });

  const { email, password, role } = parse.data;

  try {
    const updateData: any = {};
    if (email) updateData.email = email;
    if (role) updateData.role = role;
    if (password) updateData.password = await hashPassword(password);

    let user = await prisma.client.update({ where: { id }, data: updateData }).catch(() => null);
    if (!user) user = await prisma.admin.update({ where: { id }, data: updateData }).catch(() => null);
    if (!user) return res.status(404).json({ error: "User not found" });

    return res.json({ message: "User updated", user });
  } catch (err: any) {
    if (err.code === "P2002") return res.status(400).json({ error: "Email already exists" });
    return res.status(500).json({ error: "Failed to update user" });
  }
};

// ─── DELETE USER ─────────────────
export const deleteUserBySysadmin = async (req: Request, res: Response) => {
  const { id } = req.params;
  try {
    let deleted = await prisma.client.delete({ where: { id } }).catch(() => null);
    if (!deleted) deleted = await prisma.admin.delete({ where: { id } }).catch(() => null);
    if (!deleted) return res.status(404).json({ error: "User not found" });

    return res.json({ message: "User deleted" });
  } catch (err) {
    return res.status(500).json({ error: "Failed to delete user" });
  }
};




