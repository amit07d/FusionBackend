import mongoose, { Schema } from "mongoose";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";

const userSchema = new Schema(
    {
        username: {
            type: String,
            required: true,
            unique: true,
            lowercase: true,
            trim: true,
            index: true,
        },
        email: {
            type: String,
            required: true,
            unique: true,
            lowercase: true,
            trim: true,
        },
        fullName: {
            type: String,
            required: true,
            trim: true,
            index: true,
        },
        avatar: {
            type: String, // cloudinary url
            required: true,
        },
        coverImage: {
            type: String, // cloudinary url
        },
        watchHistory: [
            {
                type: Schema.Types.ObjectId,
                ref: "Video",
            },
        ],
        password: {
            type: String,
            required: [true, "Password is required"],
        },
        refreshToken: {
            type: String,
        },
    }, // last

    {
        timestamps: true,
    }
);

userSchema.pre("save", async function (next) {
    if(!this.isModified("password")) return next()
    try {
        this.password = await bcrypt.hash(this.password, 10)
        next()
    } catch (error) {
        next(error)
    }
})

userSchema.methods.isPasswordCorrect = async function (password) {
    try {
        return await bcrypt.compare(password, this.password)
    } catch (error) {
        throw new Error("Error comparing passwords")
    }
}

// Return the access token
userSchema.methods.generateAccessToken = function () {
    try {
        return jwt.sign(
            {
                id: this._id,
                email: this.email,
                username: this.username,
                fullName: this.fullName
            },
            process.env.ACCESS_TOKEN_SECRET,
            {
                expiresIn: process.env.ACCESS_TOKEN_EXPIRY
            },
        )
    } catch (error) {
        throw new Error("Error generating access token")
    }
}

// Return the refresh token
userSchema.methods.generateRefreshToken = function () {
    try {
        return jwt.sign(
            {
                id: this._id,
            },
            process.env.REFRESH_TOKEN_SECRET,
            {
                expiresIn: process.env.REFRESH_TOKEN_EXPIRY
            },
        )
    } catch (error) {
        throw new Error("Error generating refresh token")
    }
}

export const User = mongoose.model("User", userSchema);
