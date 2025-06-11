import { relations, sql } from 'drizzle-orm';
import { boolean, int, mysqlTable, varchar, timestamp, text, mysqlEnum } from 'drizzle-orm/mysql-core';

//!............................Schemas.........................................

export const shortenerTable = mysqlTable('shortener', {
  id: int().autoincrement().primaryKey(),
  url: varchar({ length: 512 }).notNull(),
  shortCode: varchar({ length: 255 }).notNull().unique(),
  createdAt: timestamp("created_at").defaultNow().notNull(), 
  updatedAt: timestamp("updated_at").defaultNow().onUpdateNow().notNull(), 
  userId : int("user_id").notNull().references(() => usersTable.id, { onDelete: "cascade" }),
});

//!Creating a schema (verifyEmailTokenTable) for verification of email
export const verifyEmailTokensTable = mysqlTable('is_email_valid', {
  id : int().autoincrement().primaryKey(),
  userId: int("user_id") .notNull() .references(() => usersTable.id, { onDelete: "cascade" }),
  token : varchar({length : 8}).notNull(),
  //!expiresAt will tell the expiry of email token
  expiresAt : timestamp('expires_at').default(sql`(CURRENT_TIMESTAMP + INTERVAL 1 DAY)`).notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull(),
})

export const usersTable = mysqlTable("users", { 
  id: int().autoincrement().primaryKey(), 
  name : varchar({ length: 255}).notNull(), 
  email: varchar({ length: 255 }).notNull().unique(),
  //!adding 'isEmailValid' for email verification icon in profile.ejs file
  isEmailValid : boolean('is_email_valid').default(false).notNull(),
  password: varchar({ length: 255}), 
  avatarURL : text('avatar_url'),
  createdAt: timestamp("created_at").defaultNow().notNull(), 
  updatedAt: timestamp("updated_at").defaultNow().onUpdateNow().notNull(), 
});

//!for using hybrid authentication
export const sessionsTable = mysqlTable("sessions", { 
  id: int().autoincrement().primaryKey(), 
  userId: int("user_id") .notNull() .references(() => usersTable.id, { onDelete: "cascade" }), //?'onDelete' means if user doesn't exists then delete data
  valid: boolean().default(true).notNull(), 
  //!userAgent stores header info such as user used OS, browser, device etc 
  userAgent: text("user_agent"),
  ip: varchar({ length: 255 }), 
  createdAt: timestamp("created_at").defaultNow().notNull(), 
  updatedAt: timestamp("updated_at").defaultNow().onUpdateNow().notNull(), 
});

//!Creating a schema (passwordResetTokenTable) for forgot password section
export const passwordResetTokensTable = mysqlTable("password_reset_tokens", { 
  id: int("id").autoincrement().primaryKey(), 
  userId: int("user_id").notNull().references(() => usersTable.id, {onDelete: "cascade" }).unique(), 
  tokenHash: text("token_hash").notNull(), 
  expiresAt: timestamp("expires_at").default(sql`(CURRENT_TIMESTAMP + INTERVAL 1 HOUR)`).notNull(), 
  createdAt: timestamp("created_at").defaultNow().notNull(), 
});

//!oauthAccountsTable 
export const oauthAccountsTable = mysqlTable("oauth_accounts", { 
  id: int("id").autoincrement().primaryKey(), 
  userId: int("user_id").notNull().references(() => usersTable.id, { onDelete: "cascade" }), 
  provider: mysqlEnum("provider", ["google", "github"]).notNull(), 
  providerAccountId: varchar("provider_account_id", { length: 255 }).notNull().unique(), 
  createdAt: timestamp("created_at").defaultNow().notNull(), 
});


//!............................Relations.........................................


//!Define relation between both tables 'usersTable and shortenerTable' if working with drizzle
//?A user can create multiple shortLinks and can have many sessions
export const userRelation = relations(usersTable, ({many}) => ({
  shortLink : many(shortenerTable),
  session : many(sessionsTable)
}))

//?A shortLink belongs to a single user
export const shortenerRelation = relations(shortenerTable, ({one}) => ({
  user : one(usersTable, {
    fields : [shortenerTable.userId],  //it is showing FK of shortenerTable
    references : [usersTable.id]
  })
}))


//?A session belongs to a single user
export const sessionRelation = relations(sessionsTable, ({one}) => ({
  user : one(usersTable, {
    fields : [sessionsTable.userId],  //it is showing FK of shortenerTable
    references : [usersTable.id]
  })
}))