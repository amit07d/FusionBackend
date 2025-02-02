import { User } from "../models/user.models.js";
import { ApiError } from "../utils/ApiError.js";
import { asyncHandler } from "../utils/asyncHandler.js";
import jwt from "jsonwebtoken";

export const verifyJwt = asyncHandler(async (req, _res, next) => {
    try {
        const token =
            req.cookies?.accessToken ||
            req.header("Authorization")?.replace("Bearer ", "");

        if (!token) {
            throw new ApiError(401, "Unauthorized request");
        }

        const decodedToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);

        if (!decodedToken?.id) {
            throw new ApiError(401, "Invalid access token");
        }

        const user = await User.findById(decodedToken.id).select("-password -refreshToken");

        if (!user) {
            throw new ApiError(401, "User not found. Invalid access token");
        }

        req.user = user;
        next();
    } catch (error) {
        next(new ApiError(401, error?.message || "Invalid access token"));
    }
});
