"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.AdminServices = void 0;
const http_status_codes_1 = __importDefault(require("http-status-codes"));
const AppError_1 = __importDefault(require("../../errorHelpers/AppError"));
const user_model_1 = __importDefault(require("../user/user.model"));
const transaction_model_1 = require("../transaction/transaction.model");
const wallet_model_1 = require("../wallet/wallet.model");
const user_interface_1 = require("../user/user.interface");
//  Get all users
const getUsers = async () => {
    const users = await user_model_1.default.find({});
    const total = await user_model_1.default.countDocuments();
    return {
        data: users,
        meta: { total },
    };
};
//  Get all agents (with user + wallet populated)
const getAgents = async () => {
    const agents = await user_model_1.default.find({ role: user_interface_1.Role.AGENT });
    const total = await user_model_1.default.countDocuments({ role: user_interface_1.Role.AGENT });
    return {
        data: agents,
        meta: { total },
    };
};
//  Get all wallets
const getWallets = async () => {
    const wallets = await wallet_model_1.Wallet.find({});
    const total = await wallet_model_1.Wallet.countDocuments();
    return {
        data: wallets,
        meta: { total },
    };
};
//  Get all transactions (sorted by latest first)
const getTransactions = async () => {
    const transactions = await transaction_model_1.Transaction.find({}).sort({ createdAt: -1 });
    const total = await transaction_model_1.Transaction.countDocuments();
    return {
        data: transactions,
        meta: { total },
    };
};
//  Block wallet
const blockWallet = async (walletId) => {
    const wallet = await wallet_model_1.Wallet.findById(walletId);
    if (!wallet) {
        throw new AppError_1.default(http_status_codes_1.default.NOT_FOUND, "Wallet not found");
    }
    wallet.status = "BLOCKED";
    wallet.isActive = false;
    await wallet.save();
    return wallet;
};
//  Unblock wallet
const unblockWallet = async (walletId) => {
    const wallet = await wallet_model_1.Wallet.findById(walletId);
    if (!wallet) {
        throw new AppError_1.default(http_status_codes_1.default.NOT_FOUND, "Wallet not found");
    }
    wallet.status = "ACTIVE";
    wallet.isActive = true;
    await wallet.save();
    return wallet;
};
// Approve Agent
const approveAgent = async (agentId) => {
    const agent = await user_model_1.default.findById(agentId);
    if (!agent) {
        throw new AppError_1.default(http_status_codes_1.default.NOT_FOUND, "Agent not found");
    }
    if (agent.role !== "AGENT") {
        throw new AppError_1.default(http_status_codes_1.default.BAD_REQUEST, "User is not an agent");
    }
    agent.status = user_interface_1.AgentActive.APPROVED;
    agent.isActive = user_interface_1.IsActive.ACTIVE; // agent active
    await agent.save();
    return agent;
};
// Suspend Agent
const suspendAgent = async (agentId) => {
    const agent = await user_model_1.default.findById(agentId);
    if (!agent) {
        throw new AppError_1.default(http_status_codes_1.default.NOT_FOUND, "Agent not found");
    }
    if (agent.role !== "AGENT") {
        throw new AppError_1.default(http_status_codes_1.default.BAD_REQUEST, "User is not an agent");
    }
    agent.status = user_interface_1.AgentActive.SUSPENDED;
    agent.isActive = user_interface_1.IsActive.BLOCKED; // agent inactive
    await agent.save();
    return agent;
};
exports.AdminServices = {
    getUsers,
    getAgents,
    getWallets,
    getTransactions,
    blockWallet,
    unblockWallet,
    approveAgent,
    suspendAgent,
};
