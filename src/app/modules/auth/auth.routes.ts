import { Router } from "express";
import { AuthControllers } from "./auth.controller";
import { Role } from "../user/user.interface";
import { checkAuth } from "../../middlewares/checkAuth";

const router = Router();

router.post("/login", AuthControllers.credentialsLogin);
router.post("/refrefreshToken", AuthControllers.getNewaccesToken);
router.post("/logout", AuthControllers.logout);
router.post(
  "/reset-password",
  checkAuth(...Object.values(Role)),
  AuthControllers.resetPassword
);
export const AuthRoutes = router;
