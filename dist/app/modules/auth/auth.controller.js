"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.AuthControllers = void 0;
const http_status_codes_1 = __importDefault(require("http-status-codes"));
const catchAsync_1 = require("../../utils/catchAsync");
const sendResponse_1 = require("../../utils/sendResponse");
const auth_service_1 = require("./auth.service");
const AppError_1 = __importDefault(require("../../errorHelpers/AppError"));
const setcookies_1 = require("../../utils/setcookies");
const credentialsLogin = (0, catchAsync_1.catchAsync)(async (req, res, next) => {
    const loginInfo = await auth_service_1.AuthServices.credentialsLogin(req.body);
    (0, setcookies_1.setAuthCookie)(res, loginInfo);
    (0, sendResponse_1.sendResponse)(res, {
        success: true,
        statusCode: http_status_codes_1.default.OK,
        message: "User Logged In Successfully",
        data: loginInfo,
    });
});
const getNewaccesToken = (0, catchAsync_1.catchAsync)(async (req, res, next) => {
    const refreshToken = req.cookies.refreshToken;
    if (!refreshToken) {
        throw new AppError_1.default(http_status_codes_1.default.BAD_REQUEST, "No refreshtoken reseive from cookies");
    }
    const tokeninfo = await auth_service_1.AuthServices.getNewaccesToken(refreshToken);
    (0, setcookies_1.setAuthCookie)(res, tokeninfo);
    (0, sendResponse_1.sendResponse)(res, {
        success: true,
        statusCode: http_status_codes_1.default.OK,
        message: "New Access Token Retrived Successfully",
        data: tokeninfo,
    });
});
exports.AuthControllers = {
    credentialsLogin,
    getNewaccesToken,
};
