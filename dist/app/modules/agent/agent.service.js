"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AgentServices = void 0;
const transaction_model_1 = require("../transaction/transaction.model");
const wallet_model_1 = require("../wallet/wallet.model");
const agent_model_1 = require("./agent.model");
const cashIn = async (agentWalletId, userWalletId, amount) => {
    // Agent wallet খুঁজে নাও
    const agentWallet = await wallet_model_1.Wallet.findById(agentWalletId);
    if (!agentWallet)
        throw new Error("Agent wallet not found");
    // Agent balance check
    if (agentWallet.balance < amount)
        throw new Error("Insufficient balance");
    // Agent থেকে balance কমাও
    agentWallet.balance -= amount;
    await agentWallet.save();
    // Receiver wallet
    const userWallet = await wallet_model_1.Wallet.findById(userWalletId);
    if (!userWallet)
        throw new Error("User wallet not found");
    userWallet.balance += amount;
    await userWallet.save();
    // Commission (Agent-এর জন্য)
    const commission = amount * 0.01;
    await agent_model_1.Agent.findOneAndUpdate({ wallet: agentWalletId }, { $inc: { commissionBalance: commission } });
    // Transaction তৈরি
    const transaction = await transaction_model_1.Transaction.create({
        senderWalletId: agentWalletId,
        receiverWalletId: userWalletId,
        type: "DEPOSIT",
        amount: amount,
        currency: "BDT",
        status: "COMPLETED",
        commission: commission, // number field
        description: `Cash-in by Agent, Commission: ${commission}`, // string field
    });
    return transaction;
};
const cashOut = async (agentWalletId, userWalletId, amount) => {
    const userWallet = await wallet_model_1.Wallet.findById(userWalletId);
    if (!userWallet)
        throw new Error("User wallet not found");
    if (userWallet.balance < amount)
        throw new Error("Insufficient balance");
    userWallet.balance -= amount;
    await userWallet.save();
    const commission = amount * 0.015;
    await agent_model_1.Agent.findOneAndUpdate({ wallet: agentWalletId }, { $inc: { commissionBalance: commission } });
    const transaction = await transaction_model_1.Transaction.create({
        senderWalletId: userWalletId,
        receiverWalletId: agentWalletId,
        type: "WITHDRAW",
        amount,
        currency: "BDT",
        status: "COMPLETED",
        description: `Cash-out by Agent, Commission: ${commission}`,
    });
    return transaction;
};
// const getCommissions = async (agentWalletId: string) => {
//   return Agent.findOne({ wallet: agentWalletId }).select("commissionBalance");
// };
// const getMyTransactions = async (walletId: string) => {
//   return Transaction.find({
//     $or: [{ senderWalletId: walletId }, { receiverWalletId: walletId }],
//   }).sort({ createdAt: -1 });
// };
exports.AgentServices = {
    cashIn,
    cashOut,
    // getCommissions,
    // getMyTransactions,
};
