import express from 'express'
import cors from 'cors'
import cookieParser from 'cookie-parser'

const app = express()

app.use(cors({
    origin: process.env.CORS_ORIGIN,
    credentials:true
}))

app.use(express.json({limit:"18kb"}))
app.use(express.urlencoded({extended:true, limit:"18kb"}))
app.use(express.static("public"))
app.use(cookieParser())


// routes import
import userRouter from "./routes/user.routes.js"

// routes declaration for routes.js
app.use("/api/v2/users", userRouter)

export { app }