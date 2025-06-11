import { log } from "console";
import {decodeIdToken, generateCodeVerifier, generateState, GitHub} from 'arctic'
import { ACCESS_TOKEN_EXPIRY, OAUTH_EXCHANGE_EXPIRY, REFRESH_TOKEN_EXPIRY } from "../config/constant.js";
import { getHtmlFromMjmlTemplate } from "../lib/get-html-from-mjml-template.js";
import { sendEmail, sendResetPasswordEmail } from "../lib/nodemailer.lib.js";
import { getUserByEmail, createUser, hashPassword, comparePassword, generateToken, createSession, createAccessToken, createRefreshToken, clearUserSession, findUserById, getAllShortLinks, generateRandomToken, insertVerifyEmailToken, createVerifyEmailLink, findVerificationEmailToken, verifyUserEmailAndUpdate, clearVerifyEmailTokens, sendVerificationEmailLink, updateUserByName, saveNewPassword, findUserByEmail, createResetPasswordLink, getResetPasswordToken, clearResetPasswordToken, getUserWithOauthId, linkUserWithOauth, createUserWithOauth } from "../services/auth.services.js";
import { emailSchema, loginUserSchema, nameSchema, registerUserSchema, setPasswordSchema, verifyEmailSchema, verifyPasswordSchema, verifyResetPasswordSchema } from "../validators/auth.validator.js";
import { google } from "../lib/oauth/google.js";
import { github } from "../lib/oauth/github.js";

export const getRegisterPage = (req, res) => {
    try {
        if(req.user) {
            return res.redirect('/');   //via JWT token
        }

        //?sending error is user exists while registering and stored via flash's error datatype
        return res.render("auth/register", {errors : req.flash('errors')})
    } catch (error) {
        console.error("Render error:", error);
        return res.status(500).send("Internal Server Error 2")
    }
}

export const getLoginPage = (req, res) => {
    if(req.user) {
        return res.redirect('/');   //via JWT token
    }

    //?sending error is user exists while logging and stored via flash's error datatype
    return res.render("auth/login", {errors : req.flash('errors')})
}

export const postLogin = async (req, res) => {
    if(req.user) {
        return redirect('/');   //via JWT token
    }
    // const {email, password} = req.body;

    //!using zod schema validation
    const {data, error} = loginUserSchema.safeParse(req.body)
    //console.log(data);
    if(error){
        const errors = error.errors[0].message;
        req.flash("errors", errors);
        return res.redirect('/login')
    }
    const {email, password} = data;

    const user = await getUserByEmail(email);
    //console.log("user exists : ",user);
    
    if(!user){
        //!using flash-connect to store in session using 'errors' datatype
        req.flash("errors", "Invalid Email or Password!!");
        return res.redirect('/login')
    }

    //!condition applied for the user who registered with OAuth only
    if(!user.password){
        req.flash('errors', "You have created account with social login. Please login with your social account.")
        return res.redirect('/login')
    }

    //!comparing userExist.password(hashed One) with password
    const isValidPassword = await comparePassword(password, user.password)

    //if user exist then check for password
    // if(userExist.password !== hashedPassword){
    //     return res.redirect('/login')
    // }

    
    if(!isValidPassword){
        req.flash("errors", "Invalid Email or Password!!");
        return res.redirect('/login')
    }


    //! setting of cookies and path is "/" because session starts from out home page and every url starting from "/".... (complex)
    // res.setHeader('Set-Cookie', 'isLoggedIn=true; path=/;')
    //?go to getShortenerPage route to get cookie value

    //! setting of cookie via cookie parser(Recommended)
    // res.cookie("isLoggedIn", true)
    //?go to getShortenerPage route to get cookie value


    //!Creating a JWT token here
    // const token = generateToken({
    //     id : user.id,
    //     name : user.name,
    //     email : user.email
    // })
    //?After generating token we will send the cookie to client's browser with token value
    // res.cookie('access-token', token);

    //!Using Hybrid Authentication..............
    //?we need to create a session first
    const session =  await createSession(user.id, {
        ip : req.clientIp,
        userAgent : req.headers['user-agent']
    })
    
    //?now we need to create accessToken
    const accessToken = createAccessToken({
        id : user.id,
        name : user.name,
        email : user.email,
        isEmailValid : user.isEmailValid,
        avatarURL : user.avatarURL,
        sessionId : session.id,
    })

    //?now we need to create refreshToken
    const refreshToken = createRefreshToken(session.id);

    //?send cookie with extra information
    const baseConfig = { httpOnly : true, secure : true} //httpOnly means no one can access with JS DOM, and secure means runs on https 

    //?After generating tokens we will send the cookie to client's browser with token value
    res.cookie('access_token', accessToken, {
        ...baseConfig,   //...baseConfig (destructuring) means 'httpOnly : true, secure : true'
        maxAge : ACCESS_TOKEN_EXPIRY
    })

    res.cookie('refresh_token', refreshToken, {
        ...baseConfig,   //...baseConfig (destructuring) means 'httpOnly : true, secure : true'
        maxAge : REFRESH_TOKEN_EXPIRY
    })

    return res.redirect('/')
}

export const postRegister = async (req, res) => {
    // const {name, email, password} = req.body;

    //!using zod schema validation
    const {data, error} = registerUserSchema.safeParse(req.body)
    //console.log(data);
    if(error){
        const errors = error.errors[0].message;
        req.flash("errors", errors);
        return res.redirect('/register')
    }
 
    const {name, email, password} = data

    const userExist = await getUserByEmail(email);
    //console.log("user exists : ",userExist);


    if(userExist){
        //!using flash-connect to store in session using 'errors' datatype
        req.flash("errors", "User already exists!");
        
        return res.redirect('/register')
    }

    //!hashing of password first then add it to database
    const hashedPassword = await hashPassword(password)
    
    const [user] = await createUser({name, email, password : hashedPassword});
    //console.log(user);  //here we are getting id only

    // return res.redirect('/login')

    //!copy and pasting session and token creation, cookie sending from postLogin for skipping manual login.........
    //!Using Hybrid Authentication..............
    //?we need to create a session first
    const session =  await createSession(user.id, {
        ip : req.clientIp,
        userAgent : req.headers['user-agent']
    })
    
    //?now we need to create accessToken
    const accessToken = createAccessToken({
        id : user.id,
        name : name,
        email : email,
        isEmailValid : false,
        avatarURL : user.avatarURL,
        sessionId : session.id,
    })

    //?now we need to create refreshToken
    const refreshToken = createRefreshToken(session.id);

    //?send cookie with extra information
    const baseConfig = { httpOnly : true, secure : true} //httpOnly means no one can access with JS DOM, and secure means runs on https 

    //?After generating tokens we will send the cookie to client's browser with token value
    res.cookie('access_token', accessToken, {
        ...baseConfig,   //...baseConfig (destructuring) means 'httpOnly : true, secure : true'
        maxAge : ACCESS_TOKEN_EXPIRY
    })

    res.cookie('refresh_token', refreshToken, {
        ...baseConfig,   //...baseConfig (destructuring) means 'httpOnly : true, secure : true'
        maxAge : REFRESH_TOKEN_EXPIRY
    })

    await sendVerificationEmailLink({
        email : email,
        userId : user.id,
        req
    })

    return res.redirect('/')
    
}

export const getMe = (req, res) => {
    if(!req.user) {
        return res.send("Not logged in")
    }
    return res.send(`<h1>Hey - ${req.user.name} - ${req.user.email}</h1>`)
}

export const getLogoutUser = async (req, res) => {
    //!clear session and cookie for proper logout
    await clearUserSession(req.user.sessionId)

    res.clearCookie('access_token')
    res.clearCookie('refresh_token')
    res.clearCookie('google_oauth_state')
    res.clearCookie('google_code_verifier')
    res.clearCookie('github_oauth_state')
    return res.redirect('/login')
}


export const getUserProfilePage = async (req, res) => {
    try {
        if (!req.user){
            return res.redirect('/login')
        }

        const user = await findUserById(req.user.id)

        if(!user){
            return res.redirect('/login')
        }

        const userShortLinks = await getAllShortLinks(user.id)
        return res.render('auth/profile', {
            user : {
                id : user.id,
                name : user.name,
                email : user.email,
                isEmailValid : user.isEmailValid,
                hasPassword : Boolean(user.password),
                avatarURL : user.avatarURL,
                createdAt : user.createdAt,
                shortLinks : userShortLinks,
            }
        });
    } catch (error) {
        console.log("profile page error : ",error.message);
    }
}

export const getVerifyEmailPage = async (req, res) => {
    if(!req.user){
        res.redirect('/register')
    }

    const user = await findUserById(req.user.id)

    if(!user || user.isEmailValid){
        res.redirect('/')
    }

    res.render('auth/verify-email', {email : req.user.email})
}

export const resendVerificationLink = async (req,res) => {
    if(!req.user){
        res.redirect('/register')
    }

    const user = await findUserById(req.user.id)

    if(!user || user.isEmailValid){
        res.redirect('/')
    }

    // //?Generating random token and email verification link
    // const randomToken = await generateRandomToken()

    // await insertVerifyEmailToken({userId : req.user.id, token : randomToken})

    // const verifyEmailLink = await createVerifyEmailLink({
    //     email : req.user.email,
    //     token : randomToken,
    // })

    // //! creating a function for sending data to node mailer
    // sendEmail({
    //     //?sending verification mail to user
    //     to : req.user.email,
    //     subject : 'Verify your email',
    //     html : `
    //         <h1>Click the below link to verify your email</h1>
    //         <p>You can use this token : <code>${randomToken}</code></p>
    //         <a href='${verifyEmailLink}'>Verify Email</a>
    //     `
    // }).catch(console.error)

    //?simplifying above code in one function so that it can be used in registration
    await sendVerificationEmailLink({
        email : req.user.email,
        userId : req.user.id,
        req : req
    })

    res.redirect('/verify-email')
}

export const verifyEmailToken = async (req, res) => {
    
    const {data, error} = verifyEmailSchema.safeParse(req.query)
    
    if(error) {
        return res.send("Verification link invalid or expired")
    }
    
    
    const token = await findVerificationEmailToken(data)

    if(!token) {
        return res.send('verification link invalid or expired')
    }

    await verifyUserEmailAndUpdate(token.email)

    await clearVerifyEmailTokens(token.userId).catch(console.error)

    return res.redirect('/profile')
}

export const getEditProfilePage = async (req, res) => {
    if(!req.user){
        return res.redirect('/login')
    }

    const user = await findUserById(req.user.id)

    if(!user){
        return res.status(404).send("user not found")
    }
    return res.render('auth/edit-profile',{
        name: user.name,
        avatarURL : user.avatarURL,
        errors : req.flash('errors')
    })
}

export const postEditProfile = async (req, res) => {
    if(!req.user){
        return res.redirect('/login')
    }

    const {name} = req.body  //req.body returns object and nameSchema cannot parse object here 
    
    const {data, error} = nameSchema.safeParse(name)
    
   
    if(error){
        const errorMessages = error.errors.map((err) => err.message)
        req.flash('errors', errorMessages)
        return res.redirect('/edit-profile')
    }
    // await updateUserByName({userId : req.user.id, name : data})

    //?now we will create file url using filename here (multer)
    const fileUrl = req.file ? `upload/avatar/${req.file.filename}` : undefined;
    await updateUserByName({userId : req.user.id, name : data, avatarURL : fileUrl})

    return res.redirect('/profile')
}

export const getChangePasswordPage = async (req, res) => {
    if(!req.user){
        return res.redirect('/login')
    }

    return res.render('auth/change-password', { errors : req.flash('errors')})
}

export const postChangePassword = async (req, res) => {
    if(!req.user){
        return res.redirect('/login')
    }

    const {data, error} = verifyPasswordSchema.safeParse(req.body)

    if(error){
        const errorMessages = error.errors.map((err) => err.message)
        req.flash('errors', errorMessages)
        return res.redirect('/change-password')
    }
    
    const {currentPassword, newPassword} = data;

    const user = await findUserById(req.user.id)

    if(!user){
        return res.status(404).send("user not found")
    }
    
    //!comparing user.password(hashed One) with currentPassword
    const isValidPassword = await comparePassword(currentPassword, user.password)

    if(!isValidPassword){
        req.flash("errors", "Current password is invalid!!");
        return res.redirect('/change-password')
    }

    await saveNewPassword({userId : user.id, newPassword})
    res.redirect('/profile')
}

export const getForgetPasswordPage = (req, res) => {
    
    return res.render('auth/forget-password', {
        errors: req.flash('errors'), 
        formSubmitted : req.flash('formSubmitted')[0], 
    })
}

export const postForgetPassword = async (req, res) => {
    //?first validate entered email
    const email = req.body.email;
    const {data, error} = emailSchema.safeParse(email);
    
    if(error){
        const errorMessages = error.errors.map((err) => err.message)
        req.flash('errors', errorMessages[0])
        return res.redirect('/forget-password')
    }

    const user = await findUserByEmail(data)
    
    
    let resetPasswordLink = null;
    if(user){
        resetPasswordLink = await createResetPasswordLink({userId : user.id, req})
    }

    //?converting mjml template to html 
    const html = await getHtmlFromMjmlTemplate("reset-password-email", {
        name : user.name,
        link : resetPasswordLink
    })

    //?send mail using smtp nodemailer
    //! creating a function for sending data to 'node mailer' or 'resend' lib files
    await sendResetPasswordEmail({
        //?sending verification mail to user
        to : user.email,
        subject : 'Reset your password',
        html 
    }).catch(console.error)

    //?if email is sent successfully then
    req.flash("formSubmitted", true)

    return res.redirect('/forget-password')
}

export const resetPasswordTokenPage = async (req, res) => {
    const {token} = req.params

    //checking in database that token exist or not
    const resetPasswordToken = await getResetPasswordToken(token)

    if(!resetPasswordToken){
        return res.render('auth/wrong-reset-password-token')
    }

    return res.render('auth/reset-password', {
        formSubmitted : req.flash('formSubmitted')[0],
        errors : req.flash('errors'),
        token
    })
}

export const postResetPasswordToken = async (req, res) => {
    //?Extract password reset token from request parameters.
    const {token} = req.params

    //?Validate token authenticity, expiration, and match with a previously issued token.
    const resetPasswordToken = await getResetPasswordToken(token)

    if(!resetPasswordToken){
        req.flash('error', 'Password token is not matching')
        return res.render('auth/wrong-reset-password-token')
    }

    //?If valid, get new password from request body and validate using a schema (e.g., Zod) for complexity.
    const {data, error} = verifyResetPasswordSchema.safeParse(req.body)

    if(error){
        const errorMessages = error.errors.map((err) => err.message)
        req.flash('errors', errorMessages[0])
        return res.redirect(`/reset-password/${token}`)
    }

    const {newPassword} = data

    //?Identify user ID linked to the token.
    const user = await findUserById(resetPasswordToken.userId)

    //?Invalidate all existing reset tokens for that user ID.
    await clearResetPasswordToken(user.id)

    //?Hash the new password with a secure algorithm
    await saveNewPassword({userId : user.id, newPassword})

    return res.redirect('/login')
}

export const getGoogleLoginPage = async (req, res) => {
    if(req.user){
        return res.redirect('/');
    }

    //?first import from 'arctic' to use these functions
    const state = generateState()

    const codeVerifier = generateCodeVerifier()

    const url = google.createAuthorizationURL(state, codeVerifier, [ 
        "openid", // this is called scopes, here we are giving openid, and profile 
        "profile", // openid gives tokens if needed, and profile gives user information 
        // we are telling google about the information that we require from user. 
        "email", 
    ]);

    const cookieConfig = { 
        httpOnly: true, 
        secure: true, 
        maxAge: OAUTH_EXCHANGE_EXPIRY, 
        sameSite: "lax", // this is such that when google redirects to our webs cookies are maintained 
    }; 

    res.cookie("google_oauth_state", state, cookieConfig); 
    res.cookie("google_code_verifier", codeVerifier, cookieConfig);
    
    res.redirect(url.toString())
}

export const getGoogleLoginCallback = async (req, res) => {
    // google redirects with code, and state in query params 
    // we will use code to find out the user 
    const { code, state } = req.query; 

    //console.log(code, state); 

    //getting cookies information
    const { google_oauth_state : storedState, google_code_verifier : codeVerifier } = req.cookies;

    //if any criteria will meet to fail then give error message on login page
    if (!code || !state || !storedState|| !codeVerifier || state !== storedState ) {
        req.flash("errors", "Couldn't login with Google because of invalid login attempt. Please try again!"); 
        return res.redirect("/login"); 
    }

    let tokens; 
    try { 
        // arctic will verify the code given by google with code verifier internally 
        tokens = await google.validateAuthorizationCode(code, codeVerifier); 
    } catch { 
        req.flash( "errors", "Couldn't login with Google because of invalid login attempt. Please try again!"); 
        return res.redirect("/login"); 
    } 

    // console.log("token google: ", tokens);

    const claims = decodeIdToken(tokens.idToken())

    //console.log('google claims : ',claims);  //!so we are also getting picture in claims

    //?validate default url of google and neglect
    

    //!we are taking profile as picture here for user
    const {sub : googleUserId, name, email, picture} = claims

    //!Once we get the user details there are few things that we should do 
    //Condition 1: User already exists with google's oauth linked 
    //Condition 2: User already exists with the same email but google's oauth isn't Linked 
    //Condition 3: User doesn't exist.

    //?if user is already linked (means present in DB in both tables) then we will get the user 
    let user = await getUserWithOauthId({ 
        provider: "google", 
        email, 
    });

    //?if user exists manually after registration and user is not linked with OAuth
    if (user && !user.providerAccountId) { 
        await linkUserWithOauth({ 
            userId: user.id, 
            provider: "google", 
            providerAccountId: googleUserId,
            avatarURL : picture     //? adding picture if user logged in first time with OAuth
        });
    }

    //? if user doesn't exist 
    if (!user) { 
        user = await createUserWithOauth({ 
            name, 
            email, 
            provider: "google", 
            providerAccountId: googleUserId,
            avatarURL : picture     //? adding picture if user logged in first time with OAuth
        })
    }

    //!now we will insert authenticate user code here(from login or signup)
    //?we need to create a session first
    const session =  await createSession(user.id, {
        ip : req.clientIp,
        userAgent : req.headers['user-agent']
    })
    
    //?now we need to create accessToken
    const accessToken = createAccessToken({
        id : user.id,
        name : name,
        email : email,
        isEmailValid : true,
        avatarURL : user.avatarURL,
        sessionId : session.id,
    })

    //?now we need to create refreshToken
    const refreshToken = createRefreshToken(session.id);

    //?send cookie with extra information
    const baseConfig = { httpOnly : true, secure : true} //httpOnly means no one can access with JS DOM, and secure means runs on https 

    //?After generating tokens we will send the cookie to client's browser with token value
    res.cookie('access_token', accessToken, {
        ...baseConfig,   //...baseConfig (destructuring) means 'httpOnly : true, secure : true'
        maxAge : ACCESS_TOKEN_EXPIRY
    })

    res.cookie('refresh_token', refreshToken, {
        ...baseConfig,   //...baseConfig (destructuring) means 'httpOnly : true, secure : true'
        maxAge : REFRESH_TOKEN_EXPIRY
    })


    return res.redirect('/')

}

export const getGithubLoginPage = async (req, res) => {
    if(req.user){
        return res.redirect('/');
    }

    //?first import from 'arctic' to use these functions
    const state = generateState()

    const url = github.createAuthorizationURL(state, ['user:email']);

    const cookieConfig = { 
        httpOnly: true, 
        secure: true, 
        maxAge: OAUTH_EXCHANGE_EXPIRY, 
        sameSite: "lax", // this is such that when google redirects to our webs, cookies are maintained 
    }; 

    res.cookie("github_oauth_state", state, cookieConfig); 
    
    res.redirect(url.toString())
}

export const getGithubLoginCallback = async (req, res) => {
    const { code, state } = req.query; 
    const { github_oauth_state: storedState} = req.cookies; 

    function handleFailedLogin() { 
        req.flash("errors", "Couldn't login with GitHub because of invalid login attempt. Please try again!"); 
        return res.redirect("/login"); 
    }

    //if any criteria will meet to fail then give error message on login page
    if (!code || !state || !storedState|| state !== storedState ) {
        return handleFailedLogin()
    }

    let tokens; 
    try { 
        // arctic will verify the code and return the token 
        tokens = await github.validateAuthorizationCode(code); 
    } catch { 
        return handleFailedLogin()
    } 

    //for fetching id and name of user with token value
    const githubUserResponse = await fetch("https://api.github.com/user", { 
        headers: { 
            Authorization: `Bearer ${tokens.accessToken()}`, 
        }, 
    }); 

    if (!githubUserResponse.ok) {
        return handleFailedLogin(); 
    }

    const githubUser = await githubUserResponse.json(); 
    //console.log('github claim : ', githubUser);  
    
    const { id: githubUserId, name, avatar_url : avatarURL} =  githubUser; //!so we are also getting picture in claims

    //for fetching email of user with token value
    const githubEmailResponse = await fetch( "https://api.github.com/user/emails", {
        headers: { 
            Authorization: `Bearer ${tokens.accessToken()}`, 
        },
    })

    if (!githubEmailResponse.ok) {
        return handleFailedLogin(); 
    }

    const emails = await githubEmailResponse.json();

    //in github we can have multiple email so we are fetching primary emails from that
    const email = emails.filter((e) => e.primary)[0].email

    if(!email) {
        return handleFailedLogin();
    }

    //!Once we get the user details there are few things that we should do 
    //Condition 1: User already exists with github's oauth linked 
    //Condition 2: User already exists with the same email but github's oauth isn't Linked 
    //Condition 3: User doesn't exist.

    //?if user is already linked (means present in DB in both tables) then we will get the user 
    let user = await getUserWithOauthId({ 
        provider: "github", 
        email, 
    });

    //?if user exists manually after registration and user is not linked with OAuth
    if (user && !user.providerAccountId) { 
        await linkUserWithOauth({ 
            userId: user.id, 
            provider: "github", 
            providerAccountId: githubUserId,
            avatarURL 
        });
    }

    //? if user doesn't exist 
    if (!user) { 
        user = await createUserWithOauth({ 
            name, 
            email, 
            provider: "github", 
            providerAccountId: githubUserId,
            avatarURL
        })
    }

    //!now we will insert authenticate user code here(from login or signup)
    //?we need to create a session first
    const session =  await createSession(user.id, {
        ip : req.clientIp,
        userAgent : req.headers['user-agent']
    })
    
    //?now we need to create accessToken
    const accessToken = createAccessToken({
        id : user.id,
        name : name,
        email : email,
        isEmailValid : true,
        avatarURL : user.avatarURL,
        sessionId : session.id,
    })

    //?now we need to create refreshToken
    const refreshToken = createRefreshToken(session.id);

    //?send cookie with extra information
    const baseConfig = { httpOnly : true, secure : true} //httpOnly means no one can access with JS DOM, and secure means runs on https 

    //?After generating tokens we will send the cookie to client's browser with token value
    res.cookie('access_token', accessToken, {
        ...baseConfig,   //...baseConfig (destructuring) means 'httpOnly : true, secure : true'
        maxAge : ACCESS_TOKEN_EXPIRY
    })

    res.cookie('refresh_token', refreshToken, {
        ...baseConfig,   //...baseConfig (destructuring) means 'httpOnly : true, secure : true'
        maxAge : REFRESH_TOKEN_EXPIRY
    })


    return res.redirect('/')
}

export const getSetPasswordPage = async (req, res) => {
    if(!req.user){
        return res.redirect('/login')
    }
    return res.render('auth/set-password', {
        errors : req.flash('errors')
    })
}

export const postSetPassword = async (req, res) => {
    const {data, error} = setPasswordSchema.safeParse(req.body)

    if(error){
        const errorMessages = error.errors.map((err) => err.message)
        req.flash('errors', errorMessages[0])
        return res.redirect(`/set-password`)
    }

    const {newPassword} = data

    const user = await findUserById(req.user.id)

    if(user.password){
        req.flash('errors', 'You have already your password, instead change your password.')
        return res.redirect('/set-password')
    }

    await saveNewPassword({userId : user.id, newPassword})
    
    return res.redirect('/profile')
}