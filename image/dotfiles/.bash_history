ls -la /var/backups/mysql/
mysqldump -u wp_user -p wordpress > /var/backups/mysql/wordpress-2026-08-30.sql
tar -czf ~/shop_backup_2026-09-01.tar.gz /var/backups/mysql/
mysql -u wp_user -p -e "SHOW TABLES;" wordpress
curl -s -o /tmp/wp.tar.gz https://wordpress.org/latest.tar.gz
ls -la /tmp/wp.tar.gz
rm /tmp/wp.tar.gz
cat /var/log/httpd/error_log | tail -30
mysql -u wp_user -p shop -e "SELECT COUNT(*) FROM orders;"
ls -la ~
pwd
whoami
cat /etc/redhat-release
