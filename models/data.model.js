// import path from 'path'
// import fs from 'fs/promises'

// //reading links from links.json (if not exists then creating that with empty object)
// const loadLinks = async (appRoot) => {
//     const jsonFilePath = path.join(appRoot, "data", "links.json")
//     try {
//         const data = await fs.readFile(jsonFilePath, "utf-8")
//         return JSON.parse(data)
//     } catch (error) {
//         if(error.code === "ENOENT"){   //ENOENT = ERROR NO ENTRY
//             await fs.writeFile(jsonFilePath, JSON.stringify({} , null, 2))
//             return {}
//         }
//         throw error
//     }
// }

// const saveLinks = async (appRoot, links) => {
//     const jsonFilePath = path.join(appRoot, "data", "links.json")
//     await fs.writeFile(jsonFilePath, JSON.stringify(links, null,2))
// }

// export {saveLinks, loadLinks}

//...........................after express........................

// import { env } from "../config/env.js";
// import { dbClient } from "../config/db-client.js";

// const db = dbClient.db(env.MONGODB_DATABASE_NAME)

// const shortenerCollection = db.collection("shorteners")

// export const loadLinks = async () => {
//     return await shortenerCollection.find().toArray()
// }

// export const saveLinks = (link) => {
//     return shortenerCollection.insertOne(link)
// }

// export const getLinksByShortcode = async (shortCode) => {
//     return await shortenerCollection.findOne({shortCode : shortCode});
// }

//...........................after mongodb........................

// import { db } from "../config/db-client.js";

//table creation
// await db.execute(`
//     create table shorteners(
//         id int auto_increment primary key,
//         shortCode varchar(512) not null,
//         url varchar(512) not null unique
//     )    
// `)


// export const loadLinks = async () => {
//     const [rows] = await db.execute(`select * from shorteners`)
//     return rows;
// }

// export const saveLinks = async (link) => {
//     return await db.execute(`insert into shorteners(shortCode, url) values(?, ?)`, [link.finalShortCode, link.url]);
// }

// export const getLinksByShortcode = async (shortCode) => {
//     const [rows] = await db.execute(`select * from shorteners where shortCode=?`, [shortCode]);
//     return rows[0];
// }


//...........................after prisma........................
import { db } from "../config/db-client.js"
import { shortenerTable } from "../drizzle/schema.js" 
import {eq} from 'drizzle-orm'

// export const loadLinks = async () => {
//     const links = await db.select().from(shortenerTable)
//     return links;
// }

export const loadLinks = async (userId) => {
    const links = await db.select().from(shortenerTable).where(eq(shortenerTable.userId, userId))
    return links;
}

// export const saveLinks = async (link) => {
//     return await db.insert(shortenerTable).values({url : link.url, shortCode : link.finalShortCode});
// }

export const saveLinks = async ({finalShortCode, url, userId}) => {
    return await db.insert(shortenerTable).values({url, shortCode : finalShortCode, userId});
}

export const getLinksByShortcode = async (shortCode) => {
    const link = await db.select().from(shortenerTable).where(eq(shortenerTable.shortCode, shortCode));
    return link;
}

export const findShortLinkById = async (id) => {
    const [result] = await db.select().from(shortenerTable).where(eq(shortenerTable.id, id))
    return result
}

export const updateShortLinkById = async ({id, url, shortCode}) => {
    const [data] = await db.update(shortenerTable).set({url : url, shortCode : shortCode}).where(eq(shortenerTable.id, id));
    return data;
}

export const deleteShortCodeById = async (id) => {
    return await db.delete(shortenerTable).where(eq(shortenerTable.id, id));
}