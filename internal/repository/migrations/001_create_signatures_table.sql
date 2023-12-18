-- Create the signatures table

CREATE TABLE signatures(
    id SERIAL PRIMARY KEY,
    "key" VARCHAR(255) NOT NULL,
    "timestamp" TIMESTAMP WITH TIME ZONE NOT NULL,
    user_id BIGINT NOT NULL,
    test JSONB
);

CREATE UNIQUE INDEX signatures_key_unique ON signatures USING btree ("key");

---- create above / drop below ----
DROP INDEX signatures_key_unique;
DROP TABLE signatures;
