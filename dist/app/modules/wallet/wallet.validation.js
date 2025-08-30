"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.withdrawSchema = exports.depositSchema = exports.createWalletSchema = void 0;
const zod_1 = require("zod");
const mongoose_1 = require("mongoose");
const wallet_interface_1 = require("./wallet.interface");
// Create Wallet Validation
exports.createWalletSchema = zod_1.z.object({
    balance: zod_1.z.number().min(0, "Balance must be minimum 0").default(50),
    currency: zod_1.z.enum(Object.values(wallet_interface_1.Currency)).default(wallet_interface_1.Currency.BDT),
    type: zod_1.z
        .enum(Object.values(wallet_interface_1.WalletType))
        .default(wallet_interface_1.WalletType.PERSONAL),
    isActive: zod_1.z.boolean().default(true),
});
// Deposit Validation
exports.depositSchema = zod_1.z.object({
    walletId: zod_1.z.string().refine((val) => mongoose_1.Types.ObjectId.isValid(val), {
        message: "Invalid WalletId",
    }),
    amount: zod_1.z.number().positive("Deposit amount must be greater than 0"),
});
// Withdraw Validation
exports.withdrawSchema = zod_1.z.object({
    walletId: zod_1.z.string().refine((val) => mongoose_1.Types.ObjectId.isValid(val), {
        message: "Invalid WalletId",
    }),
    amount: zod_1.z.number().positive("Withdraw amount must be greater than 0"),
});
