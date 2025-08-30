import { Router } from "express";
import { checkAuth } from "../../middlewares/checkAuth";
import { AgentControllers } from "./agent.controller";
import { Role } from "../user/user.interface";

const router = Router();

router.post("/cash-in", checkAuth(Role.AGENT), AgentControllers.cashIn);
router.post("/cash-out", checkAuth(Role.AGENT), AgentControllers.cashOut);
// router.get(
//   "/commissions",
//   checkAuth(Role.AGENT),
//   AgentControllers.getCommissions
// );
// router.get(
//   "/transactions/me",
//   checkAuth(Role.USER, Role.AGENT),
//   AgentControllers.getMyTransactions
// );

export const AgentRoutes = router;
