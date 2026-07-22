CREATE TABLE variant_option_values (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    product_variant_id BIGINT NOT NULL,
    option_value_id BIGINT NOT NULL,
    CONSTRAINT fk_vov_product_variant
        FOREIGN KEY (product_variant_id) REFERENCES product_variants(id)
        ON DELETE CASCADE,
    CONSTRAINT fk_vov_option_value
        FOREIGN KEY (option_value_id) REFERENCES option_values(id)
        ON DELETE CASCADE,
    CONSTRAINT uq_variant_option_value UNIQUE (product_variant_id, option_value_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;