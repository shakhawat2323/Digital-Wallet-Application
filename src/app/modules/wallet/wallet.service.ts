/* eslint-disable @typescript-eslint/no-explicit-any */
import AppError from "../../errorHelpers/AppError";
import { Wallet } from "./wallet.model";

import httpStatus from "http-status-codes";
import { Transaction } from "../transaction/transaction.model";

const createWallet = async (payload: any) => {
  const { userId, balance, currency, type, isActive } = payload;

  // check if userId is valid ObjectId
  if (!userId) {
    throw new AppError(httpStatus.BAD_REQUEST, "Invalid userId");
  }

  // check wallet exists
  const isWalletExist = await Wallet.findOne({ user: userId });
  if (isWalletExist) {
    throw new AppError(
      httpStatus.BAD_REQUEST,
      "Wallet already exists for this user"
    );
  }

  // create wallet
  const wallet = await Wallet.create({
    user: userId as string,
    balance: balance ?? 50,
    currency: currency ?? "BDT",
    type: type ?? "personal",
    status: "ACTIVE",
    isActive: isActive ?? true,
  });

  return wallet;
};

const getMyWallet = async (userId: string) => {
  const wallet = await Wallet.findOne({ user: userId });

  if (!wallet) {
    throw new AppError(httpStatus.NOT_FOUND, "Wallet not found");
  }
  return wallet;
};

// Deposit money
const depositMoney = async (walletId: string, amount: number) => {
  const wallet = await Wallet.findById(walletId);
  if (!wallet) {
    throw new AppError(httpStatus.NOT_FOUND, "Wallet not found");
  }

  wallet.balance += amount;
  await wallet.save();
  return wallet;
};

// Withdraw money
const withdrawMoney = async (walletId: string, amount: number) => {
  const wallet = await Wallet.findById(walletId);
  if (!wallet) {
    throw new AppError(httpStatus.NOT_FOUND, "Wallet not found");
  }

  if (wallet.balance < amount) {
    throw new AppError(httpStatus.BAD_REQUEST, "Insufficient balance");
  }

  wallet.balance -= amount;
  await wallet.save();
  return wallet;
};

const sendMoney = async (
  senderUserId: string,
  receiverWalletId: string,
  amount: number
) => {
  const senderWallet = await Wallet.findOne({ user: senderUserId });

  if (!senderWallet) {
    throw new AppError(httpStatus.NOT_FOUND, "Sender wallet not found");
  }

  const receiverWallet = await Wallet.findById(receiverWalletId);
  if (!receiverWallet) {
    throw new AppError(httpStatus.NOT_FOUND, "Receiver wallet not found");
  }

  if (senderWallet.balance < amount) {
    throw new AppError(httpStatus.BAD_REQUEST, "Insufficient balance");
  }

  // Balance update
  senderWallet.balance -= amount;
  receiverWallet.balance += amount;

  await senderWallet.save();
  await receiverWallet.save();

  // Transaction record create
  const transaction = await Transaction.create({
    senderWalletId: senderWallet._id,
    receiverWalletId: receiverWallet._id,
    amount,
    type: "TRANSFER",
    status: "COMPLETED",
  });

  return transaction;
};
const getMyTransactions = async (userId: string) => {
  // user এর wallet বের করা
  const senderWallet = await Wallet.findOne({ user: userId });

  if (!senderWallet) {
    throw new AppError(404, "Sender wallet not found");
  }

  const transactions = await Transaction.find({
    senderWalletId: senderWallet._id,
  })
    .populate("receiverWalletId", "user balance") // receiver এর wallet info
    .sort({ createdAt: -1 });

  return transactions;
};

export const WalletServices = {
  createWallet,
  getMyWallet,
  depositMoney,
  withdrawMoney,
  sendMoney,
  getMyTransactions,
};
