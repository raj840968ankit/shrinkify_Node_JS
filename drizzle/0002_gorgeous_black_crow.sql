ALTER TABLE `shortener` DROP FOREIGN KEY `shortener_user_id_users_id_fk`;
--> statement-breakpoint
ALTER TABLE `shortener` ADD CONSTRAINT `shortener_user_id_users_id_fk` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE cascade ON UPDATE no action;