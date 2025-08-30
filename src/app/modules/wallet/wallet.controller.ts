/* eslint-disable @typescript-eslint/no-explicit-any */
import { Request, Response } from "express";
import { WalletServices } from "./wallet.service";
import { catchAsync } from "../../utils/catchAsync";
import { sendResponse } from "../../utils/sendResponse";

// Create Wallet
const createWallet = catchAsync(async (req: Request, res: Response) => {
  const wallet = await WalletServices.createWallet(req.body);

  sendResponse(res, {
    statusCode: 201,
    success: true,
    message: "Wallet created successfully",
    data: wallet,
  });
});
// Get My Wallet
const getMyWallet = catchAsync(async (req: any, res: Response) => {
  const wallet = await WalletServices.getMyWallet(req.user._id);

  sendResponse(res, {
    statusCode: 200,
    success: true,
    message: "Wallet fetched successfully",
    data: wallet,
  });
});

// Deposit
const depositMoney = catchAsync(async (req: Request, res: Response) => {
  const { walletId, amount } = req.body;
  const wallet = await WalletServices.depositMoney(walletId, amount);

  sendResponse(res, {
    statusCode: 200,
    success: true,
    message: "Deposit successful",
    data: wallet,
  });
});

// Withdraw
const withdrawMoney = catchAsync(async (req: Request, res: Response) => {
  const { walletId, amount } = req.body;
  const wallet = await WalletServices.withdrawMoney(walletId, amount);

  sendResponse(res, {
    statusCode: 200,
    success: true,
    message: "Withdraw successful",
    data: wallet,
  });
});
// Send Money

const sendMoney = catchAsync(async (req: Request, res: Response) => {
  const { receiverWalletId, amount } = req.body;
  const senderUserId = req.user._id;

  const transaction = await WalletServices.sendMoney(
    senderUserId,
    receiverWalletId,
    amount
  );

  sendResponse(res, {
    statusCode: 200,
    success: true,
    message: "Money sent successfully",
    data: {
      senderWalletId: transaction.senderWalletId,
      receiverWalletId: transaction.receiverWalletId,
      amount: transaction.amount,
      status: transaction.status,
    },
  });
});

// Get My Transactions
export const getMyTransactions = catchAsync(
  async (req: Request, res: Response) => {
    const userId = req.user._id;

    const transactions = await WalletServices.getMyTransactions(userId);

    sendResponse(res, {
      statusCode: 200,
      success: true,
      message: "My sent transactions fetched successfully",
      data: transactions,
    });
  }
);

export const WalletControllers = {
  createWallet,
  getMyWallet,
  depositMoney,
  withdrawMoney,
  sendMoney,
  getMyTransactions,
};
