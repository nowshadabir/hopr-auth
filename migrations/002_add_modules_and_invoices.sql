-- Migration 002: Add max_accounts, modules, business_name to users + create invoices table
-- Safe to run on MySQL 8.0+ / MariaDB 10.6+

SET NAMES utf8mb4;
SET time_zone = '+00:00';

ALTER TABLE `users`
    ADD COLUMN `max_accounts` INT NULL DEFAULT NULL AFTER `subscription_expires_at`,
    ADD COLUMN `modules` JSON NULL DEFAULT NULL AFTER `max_accounts`,
    ADD COLUMN `business_name` VARCHAR(160) NULL DEFAULT NULL AFTER `modules`;

CREATE TABLE IF NOT EXISTS `invoices` (
    `id` VARCHAR(64) NOT NULL,
    `user_id` BIGINT UNSIGNED NOT NULL,
    `invoice_no` VARCHAR(64) NOT NULL,
    `data_json` LONGTEXT NOT NULL,
    `updated_at_epoch` BIGINT UNSIGNED NOT NULL,
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    KEY `idx_invoices_user_updated` (`user_id`, `updated_at_epoch`),
    CONSTRAINT `fk_invoices_user`
        FOREIGN KEY (`user_id`) REFERENCES `users` (`id`)
        ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
