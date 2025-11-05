package com.letocart.java_apirest_2026;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.web.client.RestTemplate;

@SpringBootApplication
public class JavaApirest2026Application {

    public static void main(String[] args) {
        SpringApplication.run(JavaApirest2026Application.class, args);
    }

    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }
}