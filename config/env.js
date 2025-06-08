import {z} from 'zod'

// const env = z.object({
//     PORT : z.coerce.number().default(3000),
//     MONGODB_URI : z.string(),
//     MONGODB_DATABASE_NAME : z.string()
// }).parse(process.env)       //parsing data from .env file

const env = z.object({
    PORT : z.coerce.number().default(3000),
    DATABASE_HOST : z.string(),
    DATABASE_USER : z.string(),
    DATABASE_PASSWORD : z.string(),
    DATABASE_NAME : z.string()
}).parse(process.env)       //parsing data from .env file

export {env}