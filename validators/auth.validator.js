import z from 'zod'

export const nameSchema = z
        .string()
        .trim()
        .min(3, { message: "Name must be at least 3 characters long." })
        .max(100, { message: "Name must be no more than 100 characters." })

export const emailSchema = z
        .string()
        .trim()
        .email({ message: "Please enter a valid email address." })
        .max(100, { message: "Email must be no more than 100 characters." })

export const loginUserSchema = z.object({
    email : emailSchema,

    password : z
        .string()
        .min(5, { message: "Password must be at least 5 characters long." })
        .max(100, { message: "Password must be no more than 100 characters." }),
})


export const registerUserSchema = loginUserSchema.extend({
    name : nameSchema,

    // email : z
    //     .string()
    //     .trim()
    //     .email({ message: "Please enter a valid email address." })
    //     .max(100, { message: "Email must be no more than 100 characters." }),

    // password : z
    //     .string()
    //     .min(5, { message: "Password must be at least 6 characters long." })
    //     .max(100, { message: "Password must be no more than 100 characters." }),
})

//?schema made for email verification
export const verifyEmailSchema = z.object({
    token : z.string().trim().length(8),
    email : z.string().trim().email()
})


//?change-password schema
export const verifyPasswordSchema = z.object({ 
    currentPassword: z 
        .string() 
        .min(1, { message: "Current Password is required!" }), 

    newPassword: z 
        .string() 
        .min(5, { message: "New Password must be at least 6 characters long." }) 
        .max(100, { message: "New Password must be no more than 100 characters." }), 

    confirmPassword: z 
        .string() 
        .min(5, { message: "Confirm Password must be at least 6 characters long." })
        .max(100, { message: "Confirm Password must be no more than 100 characters." }), 
        
}).refine((data) => data.newPassword === data.confirmPassword, {
    message : "Password don't match",
    path : ['ConfirmPassword']  //if error occur then it will be associated with confirm password field
}) //?refine method is used here to check both password during zod validation itself


export const verifyResetPasswordSchema = z.object({
    newPassword: z 
    .string() 
    .min(5, { message: "New Password must be at least 6 characters long." }) 
    .max(100, { message: "New Password must be no more than 100 characters." }), 

    confirmPassword: z 
        .string() 
        .min(5, { message: "Confirm Password must be at least 6 characters long." })
        .max(100, { message: "Confirm Password must be no more than 100 characters." }), 

}).refine((data) => data.newPassword === data.confirmPassword, {
    message : "Password don't match",
    path : ['ConfirmPassword']  //if error occur then it will be associated with confirm password field
})

export const setPasswordSchema = verifyResetPasswordSchema
