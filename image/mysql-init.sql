-- First-boot provisioning for the honeypot MariaDB instance.
-- NOTE: the wp_user password must match image/dotfiles/.my.cnf
-- (tests/test_honeypot_image.py asserts they agree).
CREATE DATABASE IF NOT EXISTS wordpress CHARACTER SET utf8mb4;
CREATE DATABASE IF NOT EXISTS shop CHARACTER SET utf8mb4;
CREATE USER IF NOT EXISTS 'wp_user'@'localhost' IDENTIFIED BY 'W0rdpr3ss!2024';
CREATE USER IF NOT EXISTS 'wp_user'@'%' IDENTIFIED BY 'W0rdpr3ss!2024';
GRANT ALL PRIVILEGES ON wordpress.* TO 'wp_user'@'localhost';
GRANT ALL PRIVILEGES ON wordpress.* TO 'wp_user'@'%';
GRANT SELECT ON shop.* TO 'wp_user'@'localhost';
GRANT SELECT ON shop.* TO 'wp_user'@'%';
FLUSH PRIVILEGES;
