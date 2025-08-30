import { z } from "zod";
import { Types } from "mongoose";
import { Currency, WalletType } from "./wallet.interface";

// Create Wallet Validation
export const createWalletSchema = z.object({
  balance: z.number().min(0, "Balance must be minimum 0").default(50),
  currency: z.enum(Object.values(Currency)).default(Currency.BDT),
  type: z
    .enum(Object.values(WalletType) as [string])
    .default(WalletType.PERSONAL),
  isActive: z.boolean().default(true),
});

// Deposit Validation
export const depositSchema = z.object({
  walletId: z.string().refine((val) => Types.ObjectId.isValid(val), {
    message: "Invalid WalletId",
  }),
  amount: z.number().positive("Deposit amount must be greater than 0"),
});

// Withdraw Validation
export const withdrawSchema = z.object({
  walletId: z.string().refine((val) => Types.ObjectId.isValid(val), {
    message: "Invalid WalletId",
  }),
  amount: z.number().positive("Withdraw amount must be greater than 0"),
});
