import {reset, seed} from 'drizzle-seed'
import * as schemas from './schema.js'
import { db } from '../config/db-client.js'

await reset(db, schemas) //!this will reset all schemas(if you want then run only this command)


// const USER_ID = 1; 
// await reset(db, { shortenerTable: schemas.shortenerTable }); //!it will reset shortLinks table

// //!seeding 40 values in shortLinks table for userID = 1
// await seed( 
//     db, 
//     { shortenerTable: schemas.shortenerTable }, 
//     { count: 40 } 
// ).refine((f) => ({ 
//     shortenerTable: { 
//         columns: {    //!in columns always give non-unique fields
//             userId: f.default({ defaultValue: USER_ID }), //!it tells that make seeding for particular user
//             url: f.default({ defaultValue: "https://thapatechnical.shop/" }), 
//         }, 
//     }, 
// }));
// //?after writing code, run 'npm run db:seed'

process.exit(0)