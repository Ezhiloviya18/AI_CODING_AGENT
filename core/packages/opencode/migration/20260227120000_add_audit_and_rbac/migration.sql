-- Audit log table
CREATE TABLE `audit_log` (
	`id` text PRIMARY KEY NOT NULL,
	`session_id` text REFERENCES `session`(`id`) ON DELETE SET NULL,
	`user_id` text,
	`action` text NOT NULL,
	`resource_type` text NOT NULL,
	`resource_id` text,
	`tool` text,
	`input_summary` text,
	`output_summary` text,
	`decision` text,
	`metadata` text,
	`time_created` integer NOT NULL,
	`time_updated` integer NOT NULL
);

CREATE INDEX `audit_log_session_idx` ON `audit_log` (`session_id`);
CREATE INDEX `audit_log_user_idx` ON `audit_log` (`user_id`);
CREATE INDEX `audit_log_action_idx` ON `audit_log` (`action`);
CREATE INDEX `audit_log_time_idx` ON `audit_log` (`time_created`);

-- Add user_id column to session table for tracking who created each session
ALTER TABLE `session` ADD COLUMN `user_id` text;
CREATE INDEX `session_user_idx` ON `session` (`user_id`);
