import dotenv from "dotenv";
import connectDB from "./db/index.js";
import express from 'express'

dotenv.config({
    path:"./.env"
})

const app = express()

connectDB()
    .then(() => {
        app.listen(process.env.PORT || 8000, () => {
            console.log(`Server is running at port : ${process.env.PORT}`);
            
        })
    })
    
    .catch((err) => {
    console.error("MongoDB connection failed", err);
    
})






/*
import express from 'express';
const app = express();

(async () => {
    try {
        
        await mongoose.connect(`${process.env.MONGODB_URI}/${DB_NAME}`);
        console.log("Connected to MongoDB");


        app.listen(process.env.PORT, () => {
            console.log(`App is listening on port ${process.env.PORT}`);
        });

    } catch (error) {
        console.error("Error:", error.message); 
        process.exit(1); 
    }
})();
*/
