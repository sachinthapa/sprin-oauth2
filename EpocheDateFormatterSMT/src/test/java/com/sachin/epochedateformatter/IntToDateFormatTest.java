package com.sachin.epochedateformatter;

import org.apache.kafka.connect.data.Schema;
import org.apache.kafka.connect.data.SchemaBuilder;
import org.apache.kafka.connect.data.Struct;
import org.apache.kafka.connect.source.SourceRecord;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class IntToDateFormatTest {

    private IntToDateFormat<SourceRecord> xform = new IntToDateFormat.Value<>();

    @Test
    public void copySchemaAndInsertUuidField() {
        final Map<String, Object> props = new HashMap<>();
        props.put("target.field", "published");
        xform.configure(props);

//        Schema newDateFieldSchemaExplicit = SchemaBuilder.int32()
//                .name(Date.LOGICAL_NAME)
//                .version(Date.SCHEMA.version()) // Typically 1
//                .optional()
//                .doc("The transformed date field")
//                .build();

        final Schema simpleStructSchema = SchemaBuilder.struct().name("schema_nam").version(1).doc("doc")
                .field("magic", Schema.OPTIONAL_INT32_SCHEMA)
                .field("published", Schema.INT32_SCHEMA).
                build();

//        if (!"org.apache.kafka.connect.data.Date".equals(newDateFieldSchemaExplicit.name())) {
//            throw new DataException("Requested conversion of Date object but the schema does not match.");
//        }

//        final SimpleDateFormat formatter = new SimpleDateFormat("E MMM dd HH:mm:ss zzz yyyy", Locale.ENGLISH);
        final Struct simpleStruct = new Struct(simpleStructSchema)
                .put("magic", 42)
                .put("published", 19645);

        final SourceRecord record = new SourceRecord(null, null, "test", 0, simpleStructSchema, simpleStruct);
        final SourceRecord transformedRecord = xform.apply(record);
        System.out.println("transformedRecord = " + transformedRecord);

        assertEquals(simpleStructSchema.name(), transformedRecord.valueSchema().name());
        assertEquals(simpleStructSchema.version(), transformedRecord.valueSchema().version());
        assertEquals(simpleStructSchema.doc(), transformedRecord.valueSchema().doc());

        assertEquals(Schema.OPTIONAL_INT32_SCHEMA, transformedRecord.valueSchema().field("magic").schema());
        assertEquals(42L, ((Struct) transformedRecord.value()).getInt32("magic").longValue());
        assertEquals(Schema.STRING_SCHEMA, transformedRecord.valueSchema().field("published").schema());
        assertEquals("2023-10-15", ((Struct) transformedRecord.value()).getString("published"));
        assertNotNull(((Struct) transformedRecord.value()).getString("published"));
    }

    @Test
    public void schemalessInsertUuidField() {
        final Map<String, Object> props = new HashMap<>();
        props.put("target.field", "published");
        xform.configure(props);

        final SourceRecord record = new SourceRecord(null, null, "test", 0,
                null, Collections.singletonMap("published", 1753770515));
        final SourceRecord transformedRecord = xform.apply(record);
        System.out.println("transformedRecord = " + transformedRecord);
    }
}
