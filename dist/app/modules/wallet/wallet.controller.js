"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.WalletControllers = exports.getMyTransactions = void 0;
const wallet_service_1 = require("./wallet.service");
const catchAsync_1 = require("../../utils/catchAsync");
const sendResponse_1 = require("../../utils/sendResponse");
// Create Wallet
const createWallet = (0, catchAsync_1.catchAsync)(async (req, res) => {
    const wallet = await wallet_service_1.WalletServices.createWallet(req.body);
    (0, sendResponse_1.sendResponse)(res, {
        statusCode: 201,
        success: true,
        message: "Wallet created successfully",
        data: wallet,
    });
});
// Get My Wallet
const getMyWallet = (0, catchAsync_1.catchAsync)(async (req, res) => {
    const wallet = await wallet_service_1.WalletServices.getMyWallet(req.user._id);
    (0, sendResponse_1.sendResponse)(res, {
        statusCode: 200,
        success: true,
        message: "Wallet fetched successfully",
        data: wallet,
    });
});
// Deposit
const depositMoney = (0, catchAsync_1.catchAsync)(async (req, res) => {
    const { walletId, amount } = req.body;
    const wallet = await wallet_service_1.WalletServices.depositMoney(walletId, amount);
    (0, sendResponse_1.sendResponse)(res, {
        statusCode: 200,
        success: true,
        message: "Deposit successful",
        data: wallet,
    });
});
// Withdraw
const withdrawMoney = (0, catchAsync_1.catchAsync)(async (req, res) => {
    const { walletId, amount } = req.body;
    const wallet = await wallet_service_1.WalletServices.withdrawMoney(walletId, amount);
    (0, sendResponse_1.sendResponse)(res, {
        statusCode: 200,
        success: true,
        message: "Withdraw successful",
        data: wallet,
    });
});
// Send Money
const sendMoney = (0, catchAsync_1.catchAsync)(async (req, res) => {
    const { receiverWalletId, amount } = req.body;
    const senderUserId = req.user._id;
    const transaction = await wallet_service_1.WalletServices.sendMoney(senderUserId, receiverWalletId, amount);
    (0, sendResponse_1.sendResponse)(res, {
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
exports.getMyTransactions = (0, catchAsync_1.catchAsync)(async (req, res) => {
    const userId = req.user._id;
    const transactions = await wallet_service_1.WalletServices.getMyTransactions(userId);
    (0, sendResponse_1.sendResponse)(res, {
        statusCode: 200,
        success: true,
        message: "My sent transactions fetched successfully",
        data: transactions,
    });
});
exports.WalletControllers = {
    createWallet,
    getMyWallet,
    depositMoney,
    withdrawMoney,
    sendMoney,
    getMyTransactions: exports.getMyTransactions,
};
