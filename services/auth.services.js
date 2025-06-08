import { db } from "../config/db-client.js";
import { sessionsTable, shortenerTable, usersTable, verifyEmailTokensTable } from "../drizzle/schema.js";
import { and, eq, gte, lt, sql } from "drizzle-orm";
import bcrypt from 'bcrypt'
import argon2 from 'argon2'
import jwt from 'jsonwebtoken'
import { ACCESS_TOKEN_EXPIRY, MILLISECONDS_PER_SECOND, REFRESH_TOKEN_EXPIRY } from "../config/constant.js";
import crypto from 'crypto'
import { log } from "console";
import fs from 'fs/promises'
import path from 'path'
import ejs from 'ejs'
import mjml from 'mjml';
import mjml2html from "mjml";
// import { sendEmail } from "../lib/resend.lib.js";
import { sendEmail } from "../lib/nodemailer.lib.js";

export const getUserByEmail = async (email) => {
    const [user] = await db.select().from(usersTable).where(eq(usersTable.email, email))
    return user;
}
export const createUser = async ({name, email, password}) => {
    return await db.insert(usersTable).values({name, email, password}).$returningId()
}

export const hashPassword = async (password) => {
    //return await bcrypt.hash(password, 10)  //! here we have added 10 salts [using bcrypt]
    return await argon2.hash(password)        //? salt are added itself [using argon2]
}

export const comparePassword = async (password, hash) => {
    // return await bcrypt.compare(password, hash) //! (password, hashPassword) [using bcrypt]
    return await argon2.verify(hash, password)     //? (hashPassword, password) [using argon2]
}

export const generateToken = ({id, name, email}) => {
    //syntax - jwt.sign(payload, secret key, options)
    return jwt.sign({id, name, email}, process.env.JWT_SECRET, {
        expiresIn : "30d"
    })
}

export const verifyJWTToken = (token) => {
    //syntax - 
    return jwt.verify(token, process.env.JWT_SECRET)
};


export const createSession = async (userId, {ip, userAgent}) => {
    const [session] = await db.insert(sessionsTable).values({userId, ip, userAgent}).$returningId();
    return session;
}

export const createAccessToken = ({id, name, email, isEmailValid, sessionId}) => {
    return jwt.sign({id, name, email, isEmailValid, sessionId}, process.env.JWT_SECRET, {
        expiresIn : ACCESS_TOKEN_EXPIRY / MILLISECONDS_PER_SECOND   //imported from config/constant/js
    })
}

export const createRefreshToken = (sessionId) => {
    return jwt.sign({sessionId}, process.env.JWT_SECRET, {
        expiresIn : REFRESH_TOKEN_EXPIRY / MILLISECONDS_PER_SECOND  //expires in 1 Week
    })
}

export const findSessionById = async (sessionId) => {
    const [session] = await db.select().from(sessionsTable).where(eq(sessionsTable.id, sessionId))

    return session;
}

export const findUserById = async (userId) => {
    const [user] = await db.select().from(usersTable).where(eq(usersTable.id, userId))

    return user;
}

export const refreshTokens = async (refreshToken) => {
    try {
        const decodedToken = verifyJWTToken(refreshToken);
        //now we know refreshToken has only sessionId, so with the help of it we will regenerate access_token
        //first we will get session entry that contains user id from session table and user table

        const currentSession = await findSessionById(decodedToken.sessionId)

        if(!currentSession || !currentSession.valid){
            throw new Error("Invalid session")
        }

        const user = await findUserById(currentSession.userId)
        if(!user){
            throw new Error('Invalid user')
        }

        //if we get the user then we will again generate access token and refresh token
        const userInfo = {
            id : user.id,
            name : user.name,
            email : user.email,
            isEmailValid : user.isEmailValid,
            sessionId : currentSession.id
        }

        const newAccessToken = createAccessToken(userInfo)
        const newRefreshToken = createRefreshToken(currentSession.id)

        return {newAccessToken, newRefreshToken, user : userInfo}
    } catch (error) {
        console.error('Refreshing Token Error : ',error)
    }
}

export const clearUserSession = async (sessionId) => {
    return await db.delete(sessionsTable).where(eq(sessionsTable.id, sessionId));
}

export const getAllShortLinks = async (userId) => {
    return await db.select().from(shortenerTable).where(eq(shortenerTable.userId, userId));
}


export const generateRandomToken = (digit = 8) => {
    const min = 10 ** (digit - 1)  //10000000
    const max = 10 ** (digit)  //100000000
    return crypto.randomInt(min, max).toString();
}


export const insertVerifyEmailToken = async ({userId, token}) => {
    //!using of transaction is needed because if any action fails then it will be rollback or either complete full execution
    return db.transaction(async (tx) => {
        try {
            //?it will check each row and delete the tokens of every user whose token expires matching with current timestamp
            await tx.delete(verifyEmailTokensTable).where(lt(verifyEmailTokensTable.expiresAt, sql`CURRENT_TIMESTAMP`))

            //?delete the entries having multiple tokens stored for a single specific user
            await tx.delete(verifyEmailTokensTable).where(eq(verifyEmailTokensTable.userId, userId))

            await tx.insert(verifyEmailTokensTable).values({userId, token})
        } catch (error) {
            consol.error('insertVerifyEmailToken error : ',error)
        }
    })
    
}

//! Creating Email Verification Link (Not recommended)
//add 'FRONTEND_URL' to .env file first
// export const createVerifyEmailLink = async({email , token}) => {
//     const uriEncodedEmail = encodeURIComponent(email) //this will convert ankit@gmail.com to 'ankit%40gmail.com' that browser url uses
    
//     //? '/verify-email-token' this i have given in form action after clicking verify code, the get method will append the value to it as a query parameter
//     return `${process.env.FRONTEND_URL}/verify-email-token?token=${token}&email=${uriEncodedEmail}`
// }


//! The URL API in JavaScript provides an easy way to construct, manipulate, and parse URLs without manual string concatenation. It ensures correct encoding, readability, and security when handling URLs.

//? const url = new URL("https://example.com/profile?id=42&theme=dark");

//! console.log(url.hostname); // "example.com"
//! console.log(url.pathname); // "/profile"
//! console.log(url.searchParams.get("id")); // "42"
//! console.log(url.searchParams.get("theme")); // "dark"

//* 💡 Why Use the URL API?
//? ✅ Easier URL Construction – No need for manual ? and & handling.
//? ✅ Automatic Encoding – Prevents issues with special characters.
//? ✅ Better Readability – Clean and maintainable code.

//! Creating Email Verification Link (Recommended by using URL API)
export const createVerifyEmailLink = async({email , token, req}) => {
    // const uriEncodedEmail = encodeURIComponent(email) //this will convert ankit@gmail.com to 'ankit%40gmail.com' that browser url uses
    
    // //? '/verify-email-token' this i have given in form action after clicking verify code, the get method will append the value to it as a query parameter
    // return `${process.env.FRONTEND_URL}/verify-email-token?token=${token}&email=${uriEncodedEmail}`

    
    
    const baseUrl = `${req.protocol}://${req.get('host')}`; // <-- FIX IS HERE!

    const url = new URL(`${baseUrl}/verify-email-token`);

    url.searchParams.append('token', token)
    url.searchParams.append('email', email)

    return url.toString();
}


// export const findVerificationEmailToken = async ({token, email}) => {
//     //verifying token here (if found then verified)
//     const tokenData = await db
//         .select({
//             userId : verifyEmailTokensTable.userId,
//             token : verifyEmailTokensTable.token,
//             expiresAt : verifyEmailTokensTable.expiresAt,
//         })
//         .from(verifyEmailTokensTable)
//         .where(and( eq(verifyEmailTokensTable.token, token), gte(verifyEmailTokensTable.expiresAt, sql`CURRENT_TIMESTAMP` )))

//     if(!tokenData.length){
//         return null;
//     }

//     const {userId} = tokenData[0]

//     //verifying email here (if found then verified)
//     const userData = await db
//         .select({
//             userId : usersTable.id,
//             email : usersTable.email,
//         }) 
//         .from(usersTable)
//         .where(eq(usersTable.id, userId))

//     if(!userData.length){
//         return null;
//     }

//     return {
//         userId : userData[0].userId,
//         email : userData[0].email,
//         token : tokenData[0].token,
//         expiresAt : tokenData[0].expiresAt
//     }
// }


//!Using mySql join here
export const findVerificationEmailToken = async ({token, email}) => {
    //verifying token and email both here (if found then verified)
    try {
        const tokenData = await db
        .select({
            userId : usersTable.id,
            email : usersTable.email,
            token : verifyEmailTokensTable.token,
            expiresAt : verifyEmailTokensTable.expiresAt,
        })
        .from(verifyEmailTokensTable)
        .innerJoin(usersTable, eq(usersTable.id, verifyEmailTokensTable.userId))
        .where(and( 
            eq(verifyEmailTokensTable.token, token), 
            gte(verifyEmailTokensTable.expiresAt, sql`CURRENT_TIMESTAMP`),
            eq(usersTable.email, email)
        ))
        if(!tokenData.length){
            return null;
        }

        console.log(tokenData);
        

        return {
            userId : tokenData[0].userId,
            email : tokenData[0].email,
            token : tokenData[0].token,
            expiresAt : tokenData[0].expiresAt
        }
    } catch (error) {
        console.error('findVerificationEmailToken : ',error);
        
    }
    
    
}


export const verifyUserEmailAndUpdate = async (email) => {
    return db.update(usersTable).set({isEmailValid : true}).where(eq(usersTable.email, email))
}

export const clearVerifyEmailTokens = async (userId) => {
    return await db
        .delete(verifyEmailTokensTable)
        .where(eq(verifyEmailTokensTable.userId, userId))
}

export const sendVerificationEmailLink = async ({email, userId, req}) => {
    //?Generating random token and email verification link
    const randomToken = generateRandomToken()

    await insertVerifyEmailToken({userId, token : randomToken})

    const verifyEmailLink = await createVerifyEmailLink({
        email : email,
        token : randomToken,
        req : req
    })

    //!1.Retrieving mjml Template path here
    const mjmlTemplateFile = await fs.readFile(path.join(import.meta.dirname,"..",'emails', 'verify-email.mjml'), 'utf-8')
    
    //!2.To replace the placeholder with actual value of mjml file
    const filledTemplate = ejs.render(mjmlTemplateFile, {
      code : randomToken,
      link : verifyEmailLink
    })

    //!3Convert mjml to html
    const { html: newHtmlOutput } = mjml2html(filledTemplate); // Destructure directly for cleaner code

    //! creating a function for sending data to 'node mailer' or 'resend' lib files
    await sendEmail({
        //?sending verification mail to user
        to : email,
        subject : 'Verify your email',
        // html : `
        //     <h1>Click the below link to verify your email</h1>
        //     <p>You can use this token : <code>${randomToken}</code></p>
        //     <a href='${verifyEmailLink}'>Verify Email</a>
        // `
        //?new mjml dynamic file instead of above html
        html : newHtmlOutput
    }).catch(console.error)
}