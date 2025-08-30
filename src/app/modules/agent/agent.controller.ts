/* eslint-disable @typescript-eslint/no-unused-vars */

import { NextFunction, Request, Response } from "express";
import { AgentServices } from "./agent.service";
import { sendResponse } from "../../utils/sendResponse";
import httpStatus from "http-status-codes";
import { catchAsync } from "../../utils/catchAsync";

const cashIn = catchAsync(
  async (req: Request, res: Response, next: NextFunction) => {
    const { userWalletId, amount } = req.body;

    const agentWalletId = req.user.wallet;

    const result = await AgentServices.cashIn(
      agentWalletId,
      userWalletId,
      amount
    );

    sendResponse(res, {
      success: true,
      statusCode: httpStatus.OK,
      message: "Cash-in Successful",
      data: result,
    });
  }
);
const cashOut = catchAsync(
  async (req: Request, res: Response, next: NextFunction) => {
    const { userWalletId, amount } = req.body;
    const agentWalletId = req.user.wallet;
    const result = await AgentServices.cashOut(
      agentWalletId,
      userWalletId,
      amount
    );

    sendResponse(res, {
      success: true,
      statusCode: httpStatus.OK,
      message: "Cash-in Successful",
      data: result,
    });
  }
);

export const AgentControllers = {
  cashIn,
  cashOut,
  // getCommissions,
  // getMyTransactions,
};
