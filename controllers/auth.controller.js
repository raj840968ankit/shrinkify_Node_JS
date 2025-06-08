import { ACCESS_TOKEN_EXPIRY, REFRESH_TOKEN_EXPIRY } from "../config/constant.js";
import { sendEmail } from "../lib/nodemailer.lib.js";
import { getUserByEmail, createUser, hashPassword, comparePassword, generateToken, createSession, createAccessToken, createRefreshToken, clearUserSession, findUserById, getAllShortLinks, generateRandomToken, insertVerifyEmailToken, createVerifyEmailLink, findVerificationEmailToken, verifyUserEmailAndUpdate, clearVerifyEmailTokens, sendVerificationEmailLink } from "../services/auth.services.js";
import { loginUserSchema, registerUserSchema, verifyEmailSchema } from "../validators/auth.validator.js";

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
        return res.redirect('/auth/login')
    }
    const {email, password} = data;

    
    const user = await getUserByEmail(email);
    //console.log("user exists : ",user);


    if(!user){
        //!using flash-connect to store in session using 'errors' datatype
        req.flash("errors", "Invalid Email or Password!!");
        return res.redirect('/auth/login')
    }

    //!comparing userExist.password(hashed One) with password
    const isValidPassword = await comparePassword(password, user.password)

    //if user exist then check for password
    // if(userExist.password !== hashedPassword){
    //     return res.redirect('/auth/login')
    // }

    
    if(!isValidPassword){
        req.flash("errors", "Invalid Email or Password!!");
        return res.redirect('/auth/login')
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
        return res.redirect('/auth/register')
    }
 
    const {name, email, password} = data

    const userExist = await getUserByEmail(email);
    //console.log("user exists : ",userExist);


    if(userExist){
        //!using flash-connect to store in session using 'errors' datatype
        req.flash("errors", "User already exists!");
        
        return res.redirect('/auth/register')
    }

    //!hashing of password first then add it to database
    const hashedPassword = await hashPassword(password)
    
    const [user] = await createUser({name, email, password : hashedPassword});
    //console.log(user);  //here we are getting id only

    // return res.redirect('/auth/login')

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

    return res.redirect('/auth/login')
}

export const getShortenerEditPage = (req, res) => {
    res.render('edit-shortlink')
}

export const getUserProfilePage = async (req, res) => {
    try {
        if (!req.user){
            return res.redirect('/auth/login')
        }

        const user = await findUserById(req.user.id)

        if(!user){
            return res.redirect('/auth/login')
        }

        const userShortLinks = await getAllShortLinks(user.id)
        return res.render('auth/profile', {
            user : {
                id : user.id,
                name : user.name,
                email : user.email,
                isEmailValid : user.isEmailValid,
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
        res.redirect('/')
    }

    const user = await findUserById(req.user.id)

    if(!user || user.isEmailValid){
        res.redirect('/')
    }

    res.render('auth/verify-email', {email : req.user.email})
}

export const resendVerificationLink = async (req,res) => {
    if(!req.user){
        res.redirect('/')
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
    console.log('Verify Email Token : ',token);

    if(!token) {
        return res.send('verification link invalid or expired')
    }

    await verifyUserEmailAndUpdate(token.email)

    await clearVerifyEmailTokens(token.userId).catch(console.error)

    return res.redirect('/auth/profile')
}