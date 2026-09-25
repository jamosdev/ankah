# Drop the MySQLNotification UDF and every DELIMITER-wrapped trigger block.
# The UDF is a native plugin (go-dots mysql_udf/) that feeds the CoAP signal
# channel; the demo does not build it or use the signal channel.
/^DROP FUNCTION IF EXISTS MySQLNotification/ { next }
/^CREATE FUNCTION MySQLNotification/ { next }
/^DELIMITER @@/ { skip = 1; next }
skip && /^DELIMITER ;/ { skip = 0; next }
!skip { print }
