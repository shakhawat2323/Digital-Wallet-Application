/* eslint-disable @typescript-eslint/no-non-null-assertion */
/* eslint-disable @typescript-eslint/no-unused-vars */
import bcryptjs from "bcryptjs";
import httpStatus from "http-status-codes";
import { envVars } from "../../config/env";
import AppError from "../../errorHelpers/AppError";

import { IUser } from "../user/user.interface";
import User from "../user/user.model";
import {
  createNewAccessTokenWithRefreshToken,
  createUserTokens,
} from "../../utils/userToken";
import { JwtPayload } from "jsonwebtoken";

const credentialsLogin = async (Payload: Partial<IUser>) => {
  const { email, password } = Payload;
  const isUserExist = await User.findOne({ email });
  if (!isUserExist) {
    throw new AppError(httpStatus.BAD_REQUEST, "Email dose Not exist");
  }
  const ispasswordMatched = await bcryptjs.compare(
    password as string,
    isUserExist.password as string
  );
  if (!ispasswordMatched) {
    throw new AppError(httpStatus.BAD_REQUEST, "Incorrect Password");
  }

  const userToken = createUserTokens(isUserExist);

  // delete isUserExist.password;
  const { password: pass, ...rest } = isUserExist.toObject();
  return {
    accessToken: userToken.accessToken,

    refreshToken: userToken.refreshToken,
    user: rest,
  };
};
const getNewaccesToken = async (refreshToken: string) => {
  const newAccessToken = await createNewAccessTokenWithRefreshToken(
    refreshToken
  );

  return {
    accessToken: newAccessToken,
  };
};
const resetPassword = async (
  oldpassword: string,
  newpassword: string,
  decodedToken: JwtPayload
) => {
  const user = await User.findById(decodedToken.userId);
  const isOldpasswordMatch = await bcryptjs.compare(
    oldpassword,
    user!.password as string
  );
  if (!isOldpasswordMatch) {
    throw new AppError(httpStatus.UNAUTHORIZED, "old Password does not match");
  }
  user!.password = await bcryptjs.hash(
    newpassword,
    Number(envVars.BCRYPT_SALT_ROUND)
  );
  user!.save();
};
export const AuthServices = {
  credentialsLogin,
  getNewaccesToken,
};
