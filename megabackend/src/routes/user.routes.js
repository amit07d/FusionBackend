import { Router } from "express";
import { loginUser, logoutUser, registerUser } from "../controllers/user.controller";
import { upload } from "../middlewares/multer.middleware";
import { verifyJwt } from "../middlewares/auth.middleware";

const router = Router();

router.route("/register").post(
  upload.fields([
    {
      name: "avatar",
      maxCount: 1,
    },
    {
      name: "coverImage",
      maxCount: 1,
    },
  ]),

  registerUser
);

router.route("/login").post(loginUser)

//secured route

router.route("/logout").post(verifyJwt, logoutUser)
export default router;
