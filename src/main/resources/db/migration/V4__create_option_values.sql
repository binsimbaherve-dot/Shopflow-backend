CREATE TABLE option_values (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    product_option_id BIGINT NOT NULL,
    value VARCHAR(100) NOT NULL,
    display_order INT NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_option_values_product_option
        FOREIGN KEY (product_option_id) REFERENCES product_options(id)
        ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;