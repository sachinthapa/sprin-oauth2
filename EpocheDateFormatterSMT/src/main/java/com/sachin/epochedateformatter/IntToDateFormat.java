package com.sachin.epochedateformatter;

import org.apache.kafka.common.cache.Cache;
import org.apache.kafka.common.cache.LRUCache;
import org.apache.kafka.common.cache.SynchronizedCache;
import org.apache.kafka.common.config.ConfigDef;
import org.apache.kafka.connect.connector.ConnectRecord;
import org.apache.kafka.connect.data.Field;
import org.apache.kafka.connect.data.Schema;
import org.apache.kafka.connect.data.SchemaBuilder;
import org.apache.kafka.connect.data.Struct;
import org.apache.kafka.connect.transforms.Transformation;
import org.apache.kafka.connect.transforms.util.SchemaUtil;
import org.apache.kafka.connect.transforms.util.SimpleConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.SimpleDateFormat;
import java.util.*;
import java.util.stream.Collectors;

import static org.apache.kafka.connect.transforms.util.Requirements.requireMap;
import static org.apache.kafka.connect.transforms.util.Requirements.requireStruct;

public abstract class IntToDateFormat<R extends ConnectRecord<R>> implements Transformation<R> {

    private static final String PURPOSE = "converting INT32 to date format";
    private static final Logger log = LoggerFactory.getLogger(IntToDateFormat.class);

    private interface ConfigName {
        String TARGET_FIELD = "target.field";
    }

    public static final ConfigDef CONFIG_DEF = new ConfigDef()
            .define(ConfigName.TARGET_FIELD, ConfigDef.Type.STRING, "",
                    ConfigDef.Importance.HIGH,
                    "Field name to transform");

    private String dateFieldToFormat;
    private List<Field> fieldsFiltered;
    private Cache<Schema, Schema> schemaUpdateCache;

    @Override
    public void configure(Map<String, ?> props) {
        final SimpleConfig config = new SimpleConfig(CONFIG_DEF, props);
        dateFieldToFormat = config.getString(ConfigName.TARGET_FIELD);
        schemaUpdateCache = new SynchronizedCache<>(new LRUCache<>(16));
    }

    @Override
    public R apply(R record) {
        if (operatingSchema(record) == null)
            return applySchemaless(record);
        else
            return applyWithSchema(record);
    }

    private R applySchemaless(R record) {
        final Map<String, Object> value = requireMap(operatingValue(record), PURPOSE);
        final Map<String, Object> updatedValue = new HashMap<>(value);
        updatedValue.put(dateFieldToFormat, getDateFormatted((int) value.get(dateFieldToFormat)));

        return newRecord(record, null, updatedValue);
    }

    private R applyWithSchema(R record) {
//        System.out.println(record + " > operatingValue(record):" + operatingValue(record) + " PURPOSE: " + PURPOSE);
        final Struct value = requireStruct(operatingValue(record), PURPOSE);
        final Schema oldSchema = value.schema();
//        System.out.println("value.schema(): " + value.schema());

        if (value.schema().fields().stream().noneMatch(f -> f.name().equals(dateFieldToFormat))) {
            log.warn("Field '{}' not found in schema: {}", dateFieldToFormat, value.schema().fields());
            return record;
        }

//        log.info("Schema fields available: {}",
//                value.schema().fields().stream().map(Field::name).collect(Collectors.joining(", ")));

        Schema updatedSchema = schemaUpdateCache.get(oldSchema);
        if (updatedSchema == null) {
            updatedSchema = makeUpdatedSchema(oldSchema);
            schemaUpdateCache.put(value.schema(), updatedSchema);
        }

        final Struct updatedValue = new Struct(updatedSchema);
        for (Field field : fieldsFiltered) {
//            System.out.println("updatedValue: " + field.name() + " -> " + value.get(field));
            updatedValue.put(field.name(), value.get(field));
        }
        updatedValue.put(dateFieldToFormat, getDateFormatted((int) value.get(dateFieldToFormat)));
        //        System.out.println("updatedSchema = " + updatedValue);
        return newRecord(record, updatedSchema, updatedValue);
    }

    // Debezium maps published column DATE in Postgres to INT32 representing days since epoch.
    private String getDateFormatted(int daysSinceEpoch) {
        log.info("DaysSinceEpoch(* 24 * 60 * 60 * 1000): {}", daysSinceEpoch);
        return new SimpleDateFormat("yyyy-MM-dd")
                .format(new Date((long) daysSinceEpoch * 24 * 60 * 60 * 1000));
    }

    private Schema makeUpdatedSchema(Schema schema) {
        final SchemaBuilder builder = SchemaUtil.copySchemaBasics(schema, SchemaBuilder.struct());
        fieldsFiltered = schema
                .fields()
                .stream()
                .filter(f -> !Objects.equals(f.name(), dateFieldToFormat))
                .collect(Collectors.toList());

        for (Field field : fieldsFiltered) {
//            System.out.println("copying old schema field to new schema \n-> fieldName/fieldSchema = " + field.name
//            () + "/" + field.schema());
            builder.field(field.name(), field.schema());
        }

        builder.field(dateFieldToFormat, Schema.STRING_SCHEMA);
//        System.out.println("add new to new schema \n-> fieldName/fieldSchema = " + dateFieldToFormat + "/" + Schema
//        .STRING_SCHEMA);
        return builder.build();
    }

    @Override
    public ConfigDef config() {
        return CONFIG_DEF;
    }

    @Override
    public void close() {
        schemaUpdateCache = null;
    }

    protected abstract Schema operatingSchema(R record);

    protected abstract Object operatingValue(R record);

    protected abstract R newRecord(R record, Schema updatedSchema, Object updatedValue);

    public static class Key<R extends ConnectRecord<R>> extends IntToDateFormat<R> {

        @Override
        protected Schema operatingSchema(R record) {
            return record.keySchema();
        }

        @Override
        protected Object operatingValue(R record) {
            return record.key();
        }

        @Override
        protected R newRecord(R record, Schema updatedSchema, Object updatedValue) {
            return record.newRecord(record.topic(), record.kafkaPartition(), updatedSchema, updatedValue,
                    record.valueSchema(), record.value(), record.timestamp());
        }
    }

    public static class Value<R extends ConnectRecord<R>> extends IntToDateFormat<R> {

        @Override
        protected Schema operatingSchema(R record) {
            return record.valueSchema();
        }

        @Override
        protected Object operatingValue(R record) {
            return record.value();
        }

        @Override
        protected R newRecord(R record, Schema updatedSchema, Object updatedValue) {
            return record.newRecord(record.topic(), record.kafkaPartition(), record.keySchema(), record.key(),
                    updatedSchema, updatedValue, record.timestamp());
        }

    }
}
