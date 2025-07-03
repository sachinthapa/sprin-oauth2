kafka-server-start $CONFLUENT_HOME/config/server.properties 

kafka-configs --zookeeper localhost:2181 --alter --add-config 'SCRAM-SHA-512=[password=admin-secret]' --entity-type users --entity-name admin

kafka-configs --bootstrap-server localhost:9094 --command-config server_sasl.properties --alter --add-config 'SCRAM-SHA-512=[password=alice-secret]' --entity-type users --entity-name alice

kafka-configs --bootstrap-server localhost:9094 --command-config server_sasl.properties  --describe --entity-type users --entity-name alice

kafka-console-producer --bootstrap-server localhost:9094 --command-config server_sasl.properties  --topic getting-started --property "parse.key=true" --property "key.separator=:"

kafka-console-consumer --bootstrap-server localhost:9094 --consumer.config server_sasl.properties --topic getting-started 

kafka-topics --bootstrap-server localhost:9094 --command-config config_sasl.properties  --list

