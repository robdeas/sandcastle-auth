/*
 * Copyright (c) 2025 Robert Deas
 *
 * This file is dual-licensed under the MIT License and the Apache License, Version 2.0.
 * You may choose either license to govern your use of this file.
 *
 * MIT License:
 *   Permission is hereby granted, free of charge, to any person obtaining a copy
 *   of this software and associated documentation files (the "Software"), to deal
 *   in the Software without restriction, including without limitation the rights
 *   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *   copies of the Software, and to permit persons to whom the Software is
 *   furnished to do so, subject to the following conditions:
 *
 *   [Insert full MIT license text or refer to a LICENSE file]
 *
 * Apache License, Version 2.0:
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at:
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package tech.robd.jwt;

import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

import java.io.File;

import static tech.robd.jwt.util.Constants.securityLogMarker;

@SpringBootApplication
@ConfigurationPropertiesScan("tech.robd.jwt.config")
public class JwtAuthApplication {
    public static void main(String[] args) {
        SpringApplication.run(JwtAuthApplication.class, args);
    }

    @PostConstruct
    public void createLogsDirectory() {
        File logsDir = new File("logs");
        if (!logsDir.exists()) {
            boolean created = logsDir.mkdirs();
            System.out.println("Logs directory created: " + created);
        } else {
            System.out.println("Logs directory already exists");
        }
        System.out.println("Logs directory path: " + logsDir.getAbsolutePath());
        System.out.println("Logs directory is writable: " + logsDir.canWrite());
    }

    // Add this to your main application class or any service
    @PostConstruct
    public void testLogging() {
        Logger logger = LoggerFactory.getLogger(getClass());
        logger.error("BEGIN ERROR LOG");
        logger.warn("BEGIN WARNING LOG");
        logger.info("BEGIN INFO LOG");
        logger.debug("BEGIN DEBUG LOG");
        logger.info(securityLogMarker, "BEGIN SECURITY LOG - Now logging important security events.");
    }
}