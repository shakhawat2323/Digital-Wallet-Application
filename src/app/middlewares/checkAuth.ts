import { NextFunction, Request, Response } from "express";
import { verifyToken } from "../utils/jwt";
import { envVars } from "../config/env";
import { JwtPayload } from "jsonwebtoken";
import httpStatus from "http-status-codes";
import AppError from "../errorHelpers/AppError";
import { IsActive } from "../modules/user/user.interface";
import User from "../modules/user/user.model";
import { Wallet } from "../modules/wallet/wallet.model";

export const checkAuth =
  (...authRoles: string[]) =>
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const accessToken = req.headers.authorization;
      if (!accessToken) {
        throw new AppError(403, "No Token Received");
      }

      const decoded = verifyToken(
        accessToken,
        envVars.JWT_ACCESS_SECRET
      ) as JwtPayload;
      const isUserExist = await User.findOne({ email: decoded.email }).populate(
        "wallets"
      );

      if (!isUserExist) {
        throw new AppError(httpStatus.BAD_REQUEST, "User does not exist");
      }

      if (
        isUserExist.isActive === IsActive.BLOCKED ||
        isUserExist.isActive === IsActive.INACTIVE
      ) {
        throw new AppError(
          httpStatus.BAD_REQUEST,
          `User is ${isUserExist.isActive}`
        );
      }

      if (!authRoles.includes(decoded.role)) {
        throw new AppError(403, `You are not authorized as ${decoded.role}`);
      }

      const blockedWallet = await Wallet.findOne({
        user: isUserExist._id,
        status: "BLOCKED",
      });

      if (blockedWallet) {
        throw new AppError(
          httpStatus.FORBIDDEN,
          "Your wallet is BLOCKED, no transactions allowed"
        );
      }

      let walletId;

      if (decoded.role === "AGENT" || decoded.role === "USER") {
        if (!isUserExist.wallets || isUserExist.wallets.length === 0) {
          throw new Error("User has no wallet");
        }
        walletId = isUserExist.wallets[0]._id;
      }

      req.user = {
        _id: isUserExist._id,
        email: decoded.email,
        role: decoded.role,
        wallet: walletId,
      };

      next();
    } catch (error) {
      next(error);
    }
  };
// thered code
