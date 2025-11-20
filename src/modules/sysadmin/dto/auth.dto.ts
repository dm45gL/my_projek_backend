import { z } from "zod";

const emailTransform = (val: string) => val.trim().toLowerCase();
const stringTrim = (val: string) => val.trim();

// CREATE / UPDATE User
export const createUserSchema = z.object({
  email: z.string().email({ message: "Invalid email format" }).transform(emailTransform),
  password: z
    .string()
    .min(8, { message: "Password must be at least 8 characters" })
    .regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/, {
      message: "Password must contain uppercase, lowercase, and number",
    })
    .transform(stringTrim),
  role: z.enum(["SYSADMIN", "FINANCE","BUSINESS", "CLIENT"], { message: "Role must be SYSADMIN, FINANCE, or CLIENT" }),
});

export const updateUserSchema = z.object({
  email: z.string().email({ message: "Invalid email format" }).transform(emailTransform).optional(),
  password: z
    .string()
    .min(8, { message: "Password must be at least 8 characters" })
    .regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/, {
      message: "Password must contain uppercase, lowercase, and number",
    })
    .transform(stringTrim)
    .optional(),
  role: z.enum(["SYSADMIN", "FINANCE", "CLIENT"], { message: "Role must be SYSADMIN, FINANCE, or CLIENT" }).optional(),
});
