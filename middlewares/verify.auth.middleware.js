import { ACCESS_TOKEN_EXPIRY, REFRESH_TOKEN_EXPIRY } from "../config/constant.js";
import { refreshTokens, verifyJWTToken } from "../services/auth.services.js";

//! verifying access token for JWT only
// export const verifyAuthentication = (req, res, next) => { 
//     //console.log(req.cookies);
//     // ↓↓↓ use brackets, not dot with a hyphen ↓↓↓
//     const token = req.cookies.access_token;

//     if(!token){
//         //console.log("[verifyAuthentication] → No token found, setting req.user = null");
//         req.user = null;   //defining user property null if token is not found
//         return next();
//     }
//     //otherwise
//     try {
//         const decodedToken = verifyJWTToken(token);
//         req.user = decodedToken;
//         //console.log('req.user : ',req.user);
//     } catch (error) {
//         req.user = null
//         console.error('JWT verification error -> ',error);
//     }
//     return next()
// }


//! verifying access token for hybrid authentication ( JWT + session)
export const verifyAuthentication = async (req, res, next) => {
    const accessToken = req.cookies.access_token;
    const refreshToken = req.cookies.refresh_token;

    req.user = null;

    //if nothing found then give access to next middleware simply
    if(!accessToken && !refreshToken){
        return next();
    }

    //if access token is found decode it and add req.user property
    if(accessToken){
        try {
            const decodedToken = verifyJWTToken(accessToken);
            req.user = decodedToken;
            return next();
        } catch (error) {
            console.error("Access Token Verification Error:", error.message);
        }
    }

    //if access token not found then generate access token using refresh token
    if(refreshToken){
        try {
            const {newAccessToken, newRefreshToken, user} = await refreshTokens(refreshToken)
            req.user = user;
            //now we have successfully refreshed tokens and created newAccessToken and newRefreshToken

            //now we will send cookie as response
            
            const baseConfig = { httpOnly : true, secure : true} 
        
            res.cookie('access_token', newAccessToken, {
                ...baseConfig,   
                maxAge : ACCESS_TOKEN_EXPIRY
            })
        
            res.cookie('refresh_token', newRefreshToken, {
                ...baseConfig,   
                maxAge : REFRESH_TOKEN_EXPIRY
            })

            return next();
        } catch (error) {
            console.error("Verification Refresh Token Error : ",error)
        }
    }
    return next()
}