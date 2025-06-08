import path from 'path'
import flash from 'connect-flash'
import express from 'express'
import session from 'express-session'
import cookieParser from 'cookie-parser'
import requestIp from 'request-ip'

import { authRouter } from './routes/auth.routes.js'
import {env} from './config/env.js'
import { shortenerRouter } from './routes/shortener.routes.js'
import { verifyAuthentication } from './middlewares/verify.auth.middleware.js'

const app = express()

const appRoot = import.meta.dirname;

app.set('views', path.join(appRoot, "views"))   //manually give path to ejs files(dynamic html)
app.set('view engine', 'ejs')  //using template engine(dynamic html)

//serving static file to the server
app.use(express.static(path.join(appRoot, "public")))

app.use(express.urlencoded({extended : true}))  //parses post request body

app.use(cookieParser())   //use cookie parser before hitting routes

app.use(           //using error handler and flash messages
    session({ secret: "my-secret", resave: true, saveUninitialized: false }) 
); 
app.use(flash());

app.use(requestIp.mw());   //for getting clientIP

//use verifyAuthentication middleware just after cookie parser
app.use(verifyAuthentication)   //for verification of JWT token

app.use((req, res, next) => { 
    res.locals.user = req.user; 
    return next()
});  // -> How It Works: 
// This middleware runs on every request before reaching the route handlers. 
//? res.locals is an object that persists throughout the request-response cycle. 
// If req.user exists (typically from authentication, like Passport.js), it's stored in res.locals.user. 
//Views (like EJS, Pug, or Handlebars) can directly access user without manually passing it in every route.



app.use((req, res, next) => {    //this middleware executes first then give access to route
    req.appRoot = appRoot
    next();
});

app.use(authRouter)

app.use(shortenerRouter)   //using router


app.listen(env.PORT, () => {
    console.log(`Server running at http://localhost:${env.PORT}`)
})