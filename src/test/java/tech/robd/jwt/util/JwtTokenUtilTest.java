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
package tech.robd.jwt.util;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@ActiveProfiles("test")
public class JwtTokenUtilTest {

    @Autowired
    private JwtTokenUtil jwtTokenUtil;

    private static final String USERNAME = "testuser";
    private static final List<String> ROLES = Arrays.asList("USER", "ADMIN");
    private static final String DOMAIN = "testdomain";

    private String token;

    @BeforeEach
    public void setup() {
        token = jwtTokenUtil.generateToken(USERNAME, ROLES, DOMAIN, true);
    }

    @Test
    public void testTokenGeneration() {
        assertNotNull(token);
        assertTrue(token.length() > 0);
    }

    @Test
    public void testTokenValidation() {
        assertTrue(jwtTokenUtil.validateToken(token));
    }

    @Test
    public void testGetUsernameFromToken() {
        assertEquals(USERNAME, jwtTokenUtil.getUsernameFromToken(token));
    }

    @Test
    public void testGetRolesFromToken() {
        Collection<String> extractedRoles = jwtTokenUtil.getRolesFromToken(token);
        assertEquals(2, extractedRoles.size());
        assertTrue(extractedRoles.contains("USER"));
        assertTrue(extractedRoles.contains("ADMIN"));
    }

    @Test
    public void testInvalidToken() {
        assertFalse(jwtTokenUtil.validateToken("invalid.token.string"));
    }

    @Test
    public void testTokenWithoutDomain() {
        String tokenWithoutDomain = jwtTokenUtil.generateToken(USERNAME, ROLES, null, false);
        assertTrue(jwtTokenUtil.validateToken(tokenWithoutDomain));
        // No assertion for domain since getDomainFromToken doesn't exist
    }
}

