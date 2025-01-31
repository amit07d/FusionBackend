import { v2 as cloudinary } from 'cloudinary';
import fs from 'fs';

// Configuration
if (!process.env.CLOUDINARY_CLOUD_NAME || !process.env.CLOUDINARY_API_KEY || !process.env.CLOUDINARY_API_SECRET) {
    throw new Error('Cloudinary configuration is missing! Please set CLOUDINARY_CLOUD_NAME, CLOUDINARY_API_KEY, and CLOUDINARY_API_SECRET in your environment variables.');
}

cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

// Function to upload file to Cloudinary
const uploadOnCloudinary = async (localfilePath) => {
    try {
        if (!localfilePath) {
            console.error('Local file path is missing!');
            return null;
        }

        // Upload file to Cloudinary
        const response = await cloudinary.uploader.upload(localfilePath, {
            resource_type: 'auto' // Automatically detect resource type
        });
        console.log("File uploaded to Cloudinary successfully:", response.url);
        return response;

    } catch (error) {
        console.error("Error uploading to Cloudinary:", error);

        // Attempt to delete the local file (if it exists)
        fs.unlink(localfilePath, (err) => {
            if (err) console.error("Error deleting local file:", err);
        });

        return null;
    }
};

export { uploadOnCloudinary };
