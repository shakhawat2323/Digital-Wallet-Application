/* eslint-disable @typescript-eslint/no-explicit-any */
import express, { Request, Response } from "express";
import cookieParser from "cookie-parser";
import cors from "cors";

import { router } from "./app/routes";

import { globalErrorHandler } from "./app/middlewares/globalErrorHandler";
import notFound from "./app/middlewares/notFound";

const app = express();

app.use(cookieParser());
app.use(express.json());
app.use(cors());
app.use("/api/v1", router);

app.get("/", (req: Request, res: Response) => {
  res.status(200).json({
    message: "Walcome to Digital Wallet",
  });
});

app.use(globalErrorHandler);
app.use(notFound);

export default app;
