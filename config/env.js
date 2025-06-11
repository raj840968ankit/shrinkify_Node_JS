import {z} from 'zod'

// const env = z.object({
//     PORT : z.coerce.number().default(3000),
//     MONGODB_URI : z.string(),
//     MONGODB_DATABASE_NAME : z.string()
// }).parse(process.env)       //parsing data from .env file

// const env = z.object({
//     PORT : z.coerce.number().default(3000),
//     DATABASE_HOST : z.string(),
//     DATABASE_USER : z.string(),
//     DATABASE_PASSWORD : z.string(),
//     DATABASE_NAME : z.string()
// }).parse(process.env)       //parsing data from .env file

// export {env}

const envSchema = z.object({
    GOOGLE_CLIENT_ID : z.string().min(1),
    GOOGLE_CLIENT_SECRET : z.string().min(1),
    GITHUB_CLIENT_ID : z.string().min(1),
    GITHUB_CLIENT_SECRET : z.string().min(1),
    FRONTEND_URL : z.string().url().trim().min(1),
})

export const env = envSchema.parse(process.env);