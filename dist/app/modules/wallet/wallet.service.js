"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.WalletServices = void 0;
/* eslint-disable @typescript-eslint/no-explicit-any */
const AppError_1 = __importDefault(require("../../errorHelpers/AppError"));
const wallet_model_1 = require("./wallet.model");
const http_status_codes_1 = __importDefault(require("http-status-codes"));
const transaction_model_1 = require("../transaction/transaction.model");
const createWallet = async (payload) => {
    const { userId, balance, currency, type, isActive } = payload;
    // check if userId is valid ObjectId
    if (!userId) {
        throw new AppError_1.default(http_status_codes_1.default.BAD_REQUEST, "Invalid userId");
    }
    // check wallet exists
    const isWalletExist = await wallet_model_1.Wallet.findOne({ user: userId });
    if (isWalletExist) {
        throw new AppError_1.default(http_status_codes_1.default.BAD_REQUEST, "Wallet already exists for this user");
    }
    // create wallet
    const wallet = await wallet_model_1.Wallet.create({
        user: userId,
        balance: balance ?? 50,
        currency: currency ?? "BDT",
        type: type ?? "personal",
        status: "ACTIVE",
        isActive: isActive ?? true,
    });
    return wallet;
};
const getMyWallet = async (userId) => {
    const wallet = await wallet_model_1.Wallet.findOne({ user: userId });
    if (!wallet) {
        throw new AppError_1.default(http_status_codes_1.default.NOT_FOUND, "Wallet not found");
    }
    return wallet;
};
// Deposit money
const depositMoney = async (walletId, amount) => {
    const wallet = await wallet_model_1.Wallet.findById(walletId);
    if (!wallet) {
        throw new AppError_1.default(http_status_codes_1.default.NOT_FOUND, "Wallet not found");
    }
    wallet.balance += amount;
    await wallet.save();
    return wallet;
};
// Withdraw money
const withdrawMoney = async (walletId, amount) => {
    const wallet = await wallet_model_1.Wallet.findById(walletId);
    if (!wallet) {
        throw new AppError_1.default(http_status_codes_1.default.NOT_FOUND, "Wallet not found");
    }
    if (wallet.balance < amount) {
        throw new AppError_1.default(http_status_codes_1.default.BAD_REQUEST, "Insufficient balance");
    }
    wallet.balance -= amount;
    await wallet.save();
    return wallet;
};
const sendMoney = async (senderUserId, receiverWalletId, amount) => {
    const senderWallet = await wallet_model_1.Wallet.findOne({ user: senderUserId });
    if (!senderWallet) {
        throw new AppError_1.default(http_status_codes_1.default.NOT_FOUND, "Sender wallet not found");
    }
    const receiverWallet = await wallet_model_1.Wallet.findById(receiverWalletId);
    if (!receiverWallet) {
        throw new AppError_1.default(http_status_codes_1.default.NOT_FOUND, "Receiver wallet not found");
    }
    if (senderWallet.balance < amount) {
        throw new AppError_1.default(http_status_codes_1.default.BAD_REQUEST, "Insufficient balance");
    }
    // Balance update
    senderWallet.balance -= amount;
    receiverWallet.balance += amount;
    await senderWallet.save();
    await receiverWallet.save();
    // Transaction record create
    const transaction = await transaction_model_1.Transaction.create({
        senderWalletId: senderWallet._id,
        receiverWalletId: receiverWallet._id,
        amount,
        type: "TRANSFER",
        status: "COMPLETED",
    });
    return transaction;
};
const getMyTransactions = async (userId) => {
    // user এর wallet বের করা
    const senderWallet = await wallet_model_1.Wallet.findOne({ user: userId });
    if (!senderWallet) {
        throw new AppError_1.default(404, "Sender wallet not found");
    }
    const transactions = await transaction_model_1.Transaction.find({
        senderWalletId: senderWallet._id,
    })
        .populate("receiverWalletId", "user balance") // receiver এর wallet info
        .sort({ createdAt: -1 });
    return transactions;
};
exports.WalletServices = {
    createWallet,
    getMyWallet,
    depositMoney,
    withdrawMoney,
    sendMoney,
    getMyTransactions,
};
