"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.AuthServices = void 0;
/* eslint-disable @typescript-eslint/no-non-null-assertion */
/* eslint-disable @typescript-eslint/no-unused-vars */
const bcryptjs_1 = __importDefault(require("bcryptjs"));
const http_status_codes_1 = __importDefault(require("http-status-codes"));
const env_1 = require("../../config/env");
const AppError_1 = __importDefault(require("../../errorHelpers/AppError"));
const user_model_1 = __importDefault(require("../user/user.model"));
const userToken_1 = require("../../utils/userToken");
const credentialsLogin = async (Payload) => {
    const { email, password } = Payload;
    const isUserExist = await user_model_1.default.findOne({ email });
    if (!isUserExist) {
        throw new AppError_1.default(http_status_codes_1.default.BAD_REQUEST, "Email dose Not exist");
    }
    const ispasswordMatched = await bcryptjs_1.default.compare(password, isUserExist.password);
    if (!ispasswordMatched) {
        throw new AppError_1.default(http_status_codes_1.default.BAD_REQUEST, "Incorrect Password");
    }
    const userToken = (0, userToken_1.createUserTokens)(isUserExist);
    // delete isUserExist.password;
    const { password: pass, ...rest } = isUserExist.toObject();
    return {
        accessToken: userToken.accessToken,
        refreshToken: userToken.refreshToken,
        user: rest,
    };
};
const getNewaccesToken = async (refreshToken) => {
    const newAccessToken = await (0, userToken_1.createNewAccessTokenWithRefreshToken)(refreshToken);
    return {
        accessToken: newAccessToken,
    };
};
const resetPassword = async (oldpassword, newpassword, decodedToken) => {
    const user = await user_model_1.default.findById(decodedToken.userId);
    const isOldpasswordMatch = await bcryptjs_1.default.compare(oldpassword, user.password);
    if (!isOldpasswordMatch) {
        throw new AppError_1.default(http_status_codes_1.default.UNAUTHORIZED, "old Password does not match");
    }
    user.password = await bcryptjs_1.default.hash(newpassword, Number(env_1.envVars.BCRYPT_SALT_ROUND));
    user.save();
};
exports.AuthServices = {
    credentialsLogin,
    getNewaccesToken,
};
