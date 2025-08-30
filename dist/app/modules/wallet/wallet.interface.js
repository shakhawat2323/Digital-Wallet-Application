"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Currency = exports.Status = exports.WalletType = void 0;
/** Wallet Types */
var WalletType;
(function (WalletType) {
    WalletType["PERSONAL"] = "PERSONAL";
    WalletType["BUSINESS"] = "BUSINESS";
})(WalletType || (exports.WalletType = WalletType = {}));
var Status;
(function (Status) {
    Status["ACTIVE"] = "ACTIVE";
    Status["BLOCKED"] = "BLOCKED";
})(Status || (exports.Status = Status = {}));
var Currency;
(function (Currency) {
    Currency["USD"] = "USD";
    Currency["BDT"] = "BDT";
    Currency["EUR"] = "EUR";
    Currency["INR"] = "INR";
})(Currency || (exports.Currency = Currency = {}));
