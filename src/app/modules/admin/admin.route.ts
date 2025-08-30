import { Router } from "express";
import { checkAuth } from "../../middlewares/checkAuth";
import { AdminControllers } from "./admin.controller";
import { Role } from "../user/user.interface";

const router = Router();

router.get("/users", checkAuth(Role.ADMIN), AdminControllers.getUsers);
router.get("/agents", checkAuth(Role.ADMIN), AdminControllers.getAgents);
router.get("/wallets", checkAuth(Role.ADMIN), AdminControllers.getWallets);
router.get(
  "/transactions",
  checkAuth(Role.ADMIN),
  AdminControllers.getTransactions
);

router.patch(
  "/wallets/block/:id",
  checkAuth(Role.ADMIN),
  AdminControllers.blockWallet
);
router.patch(
  "/wallets/unblock/:id",
  checkAuth(Role.ADMIN),
  AdminControllers.unblockWallet
);

router.patch(
  "/agents/approve/:id",
  checkAuth(Role.ADMIN),
  AdminControllers.approveAgent
);
router.patch(
  "/agents/suspend/:id",
  checkAuth(Role.ADMIN),
  AdminControllers.suspendAgent
);

export const AdminRoutes = router;
