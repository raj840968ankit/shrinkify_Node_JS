// import { MongoClient } from 'mongodb'
// import {env} from './env.js'

// const dbClient  = new MongoClient(env.MONGODB_URI)

// await dbClient.connect()

// export {dbClient}

// import mysql from 'mysql2/promise'
// import {env} from './env.js'

// // Step 1: Connect without specifying the database
// const tempDb = await mysql.createConnection({
//   host: env.DATABASE_HOST,
//   user: env.DATABASE_USER,
//   password: env.DATABASE_PASSWORD
// });

// // Step 2: Create the database if it doesn't exist
// await tempDb.execute(`CREATE DATABASE IF NOT EXISTS \`${env.DATABASE_NAME}\``);
// await tempDb.end();

// Step 3: Connect to the actual database
// export const db = await mysql.createConnection({
//   host: env.DATABASE_HOST,
//   user: env.DATABASE_USER,
//   password: env.DATABASE_PASSWORD,
//   database: env.DATABASE_NAME
// });


import {drizzle} from "drizzle-orm/mysql2"

export const db = drizzle(process.env.DATABASE_URL);   //connection created

