import { Transaction } from "../transaction/transaction.model";
import { Wallet } from "../wallet/wallet.model";
import { Agent } from "./agent.model";

const cashIn = async (
  agentWalletId: string,
  userWalletId: string,
  amount: number
) => {
  // Agent wallet খুঁজে নাও
  const agentWallet = await Wallet.findById(agentWalletId);
  if (!agentWallet) throw new Error("Agent wallet not found");

  // Agent balance check
  if (agentWallet.balance < amount) throw new Error("Insufficient balance");

  // Agent থেকে balance কমাও
  agentWallet.balance -= amount;
  await agentWallet.save();

  // Receiver wallet
  const userWallet = await Wallet.findById(userWalletId);
  if (!userWallet) throw new Error("User wallet not found");

  userWallet.balance += amount;
  await userWallet.save();

  // Commission (Agent-এর জন্য)
  const commission = amount * 0.01;
  await Agent.findOneAndUpdate(
    { wallet: agentWalletId },
    { $inc: { commissionBalance: commission } }
  );

  // Transaction তৈরি
  const transaction = await Transaction.create({
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

const cashOut = async (
  agentWalletId: string,
  userWalletId: string,
  amount: number
) => {
  const userWallet = await Wallet.findById(userWalletId);

  if (!userWallet) throw new Error("User wallet not found");

  if (userWallet.balance < amount) throw new Error("Insufficient balance");

  userWallet.balance -= amount;
  await userWallet.save();

  const commission = amount * 0.015;
  await Agent.findOneAndUpdate(
    { wallet: agentWalletId },
    { $inc: { commissionBalance: commission } }
  );

  const transaction = await Transaction.create({
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

export const AgentServices = {
  cashIn,
  cashOut,
  // getCommissions,
  // getMyTransactions,
};
