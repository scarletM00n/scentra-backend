import { Request , Response } from "express";
import multer from "multer";
import { randomInt } from "crypto";
import { auth_services } from "../services/auth.service";
import { toPublicUploadPath } from "../utils/uploadFile";
import { getFirebaseAdmin, sendOTPEmail, verifyOTP } from "../services/emailService";
import { prisma } from "../model/prisma";

const authService = new auth_services() ;
const firebaseAdmin = getFirebaseAdmin();

export const register = async (req: Request, res: Response) => {

    try {
        const { full_name, email, password } = req.body;

        if(!full_name || !email || !password){
            res.status(400).json({
                msg : "All fields are required"
            });
            return;
        }

        const result = await authService.registerService(full_name, email, password);

        res.status(201).json({
            msg : "User registered. Please verify your email.",
            data : result
        });
    }
    catch(err : any){
        res.status(400).json({
            msg : err.message 
        });
    }
}

export const signup = async (req: Request, res: Response) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            res.status(400).json({
                error: "Email and password are required",
            });
            return;
        }

        const normalizedEmail = String(email).trim().toLowerCase();

        try {
            await firebaseAdmin.auth().getUserByEmail(normalizedEmail);
            res.status(400).json({ error: "Email already registered" });
            return;
        } catch (error: any) {
            if (error?.code !== "auth/user-not-found") {
                throw error;
            }
        }

        // Generates a 6-digit OTP from 100000 to 999999.
        const otp = randomInt(100000, 1000000);
        const emailSent = await sendOTPEmail(normalizedEmail, otp);
        if (!emailSent) {
            res.status(500).json({ error: "Failed to send OTP email" });
            return;
        }

        res.status(200).json({
            message: "OTP sent to email",
            email: normalizedEmail,
        });
    } catch (error) {
        console.error("Signup error:", error);
        res.status(500).json({ error: "Signup failed" });
    }
}

export const verifyOtpAndCreateUser = async (req: Request, res: Response) => {
    try {
        const { email, otp, password } = req.body;

        if (!email || !otp || !password) {
            res.status(400).json({
                error: "Email, OTP, and password are required",
            });
            return;
        }

        const normalizedEmail = String(email).trim().toLowerCase();
        const isValid = await verifyOTP(normalizedEmail, otp);
        if (!isValid) {
            res.status(400).json({ error: "Invalid or expired OTP" });
            return;
        }

        const userRecord = await firebaseAdmin.auth().createUser({
            email: normalizedEmail,
            password: String(password),
        });

        try {
            await firebaseAdmin.firestore().collection("users").doc(userRecord.uid).set({
                email: normalizedEmail,
                createdAt: firebaseAdmin.firestore.FieldValue.serverTimestamp(),
                verified: true,
            });

            const prismaUpdateResult = await prisma.user.updateMany({
                where: {
                    email: normalizedEmail,
                    is_email_verified: false,
                },
                data: {
                    is_email_verified: true,
                    email_verification_code_hash: null,
                    email_verification_code_expires_at: null,
                    email_verification_sent_at: null,
                },
            });

            if (prismaUpdateResult.count === 0) {
                const prismaUser = await prisma.user.findUnique({
                    where: {
                        email: normalizedEmail,
                    },
                    select: {
                        is_email_verified: true,
                    },
                });

                if (prismaUser && !prismaUser.is_email_verified) {
                    throw new Error(
                        `Email verification update affected 0 rows while user remains unverified for ${normalizedEmail}`,
                    );
                }
            }

            await firebaseAdmin.firestore().collection("otps").doc(normalizedEmail).delete();
        } catch (firestoreError) {
            try {
                await firebaseAdmin.auth().deleteUser(userRecord.uid);
            } catch (rollbackError) {
                console.error("Failed to rollback Firebase Auth user after Firestore error:", rollbackError);
            }

            throw firestoreError;
        }

        res.status(200).json({
            message: "User created successfully",
            uid: userRecord.uid,
        });
    } catch (error: any) {
        console.error("OTP verification error:", error);

        if (error?.code === "auth/email-already-exists") {
            res.status(400).json({ error: "Email already registered" });
            return;
        }

        res.status(500).json({ error: "Verification failed" });
    }
}

export const Login = async (req : Request , res : Response) =>{

    try {
        const {email , password} = req.body ;
        
        if(!email || !password){
            res.status(400).json({
                msg : "Email and password are required"
            });
            return;
        }

        const result = await authService.loginService(email , password) ;

        res.status(200).json({
            result
        });
    }
    catch(err : any){
        if (err.message === "EMAIL_NOT_VERIFIED") {
            res.status(403).json({
                msg: "Email is not verified. Please verify before signing in.",
            });
            return;
        }

        res.status(400).json({
            msg : err.message
        });
    }
}

export const verifyEmail = async (req: Request, res: Response) => {
    try {
        const { email, code } = req.body;

        if (!email || !code) {
            res.status(400).json({
                msg: "Email and verification code are required",
            });
            return;
        }

        const result = await authService.verifyEmailService(email, code);

        res.status(200).json({
            msg: result.message,
        });
    }
    catch (err: any) {
        res.status(400).json({
            msg: err.message,
        });
    }
}

export const resendVerification = async (req: Request, res: Response) => {
    try {
        const { email } = req.body;

        if (!email) {
            res.status(400).json({
                msg: "Email is required",
            });
            return;
        }

        const result = await authService.resendVerificationService(email);

        res.status(200).json({
            msg: result.message,
        });
    }
    catch (err: any) {
        res.status(400).json({
            msg: err.message,
        });
    }
}

export const getMe = async(req : any , res : Response) =>{
    try {

        const userId = req.user.userId ;
        if (!userId) {
            res.status(401).json({
                msg : "Unauthorized"
            });
            return;
        }

        const user = await authService.getMeService(userId) ;

        res.status(200).json({
            user
        });
    }
    catch(err : any){
        if (err.message === "User not found") {
            res.status(401).json({
                msg : "Invalid session. Please login again"
            });
            return;
        }

        res.status(400).json({
            msg : err.message 
        });
    }
}

export const getMyStats = async (req: any, res: Response) => {
    try {
        const userId = req.user.userId;
        if (!userId) {
            res.status(401).json({
                msg : "Unauthorized"
            });
            return;
        }

        const stats = await authService.getMyStatsService(userId);

        res.status(200).json({
            stats,
        });
    }
    catch (err: any) {
        if (err.message === "User not found") {
            res.status(401).json({
                msg : "Invalid session. Please login again"
            });
            return;
        }

        res.status(400).json({
            msg: err.message,
        });
    }
}

export const updateProfile = async(req : any ,  res : Response) =>{

    try{
        const userId = req.user.userId ;
        const {full_name , phone, avatar_url} = req.body ;

        const result = await authService.updateProfileService(userId , {full_name , phone, avatar_url});

        res.status(200).json({
            result
        });
    }
    catch(err : any){
        res.status(400).json({
            msg : err.message
        });
    }
}

export const uploadAvatarImage = async (req: any, res: Response) => {
    try {
        const userId = req.user.userId;

        if (!req.file) {
            res.status(400).json({
                msg: "Avatar image is required",
            });
            return;
        }

        const avatarUrl = toPublicUploadPath(req.file.path);
        const result = await authService.updateAvatarService(userId, avatarUrl);

        res.status(200).json({
            msg: "Avatar uploaded successfully",
            result,
        });
    }
    catch (err: any) {
        if (err instanceof multer.MulterError) {
            const statusCode = err.code === "LIMIT_FILE_SIZE" ? 413 : 400;
            res.status(statusCode).json({
                msg: err.message,
            });
            return;
        }

        res.status(400).json({
            msg: err.message,
        });
    }
}

export const removeAvatarImage = async (req: any, res: Response) => {
    try {
        const userId = req.user.userId;
        const result = await authService.removeAvatarService(userId);

        res.status(200).json({
            msg: "Avatar removed successfully",
            result,
        });
    }
    catch (err: any) {
        res.status(400).json({
            msg: err.message,
        });
    }
}

export const changePassword  = async(req : any , res : Response) =>{

    try{
        const userId = req.user.userId ;
        const { old_password, new_password } = req.body;

        if(!old_password || !new_password){
            res.status(400).json({ message: 'All fields are required' });
            return;
        }

        await authService.changePasswordService(userId , old_password , new_password) ;

        res.status(200).json({
            msg : "Password changed successfully"
        });
    }
    catch(err : any){
        res.status(400).json({
            msg : err.message
        });
    }
}

export const logout = async(req : any , res : Response) =>{

    try{
        const userId = req.user.userId ;
        const result = await authService.logoutService(userId);

        res.status(200).json(result);
    }
    catch(err : any){
        res.status(400).json({
            msg : err.message
        });
    }
}
