import { Document, Types } from "mongoose";

export interface IAgent extends Document {
  user: Types.ObjectId; // Agent is linked to a User
  wallet: Types.ObjectId; // Agent’s Wallet
  commissionBalance: number; // Total commission earned
}
