-- Minimum go-dots state for the demo.
--
-- customer 1 is the Ankah DOTS client. go-dots maps the client certificate
-- subject CN to customer.common_name, and only accepts ACL destinations
-- inside that customer's ADDRESS_RANGE prefixes. Ankah may therefore only
-- filter traffic to its own frontend address, 172.30.0.11/32.
INSERT INTO `customer` (`id`, `common_name`, `created`, `updated`)
VALUES (1, 'ankah-demo-client', NOW(), NOW());

INSERT INTO `prefix` (`customer_id`, `mitigation_scope_id`, `type`, `addr`, `prefix_len`, `created`, `updated`)
VALUES (1, 0, 'ADDRESS_RANGE', '172.30.0.11', 32, NOW(), NOW());

-- The edge process enforces data channel ACLs itself (External-ACL blocker
-- type added by the demo's go-dots patch 0002).
INSERT INTO `blocker` (`id`, `blocker_type`, `capacity`, `load`, `created`, `updated`)
VALUES (1, 'External-ACL', 100000, 0, NOW(), NOW());

INSERT INTO `blocker_configuration` (`id`, `customer_id`, `target_type`, `blocker_type`, `created`, `updated`)
VALUES (1, 1, 'datachannel_acl', 'External-ACL', NOW(), NOW());
