
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
package tech.robd.jwt.integration;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import tech.robd.jwt.controller.AuthRequest;
import tech.robd.jwt.entity.Domain;
import tech.robd.jwt.entity.Role;
import tech.robd.jwt.entity.User;
import tech.robd.jwt.repository.DomainRepository;
import tech.robd.jwt.repository.RoleRepository;
import tech.robd.jwt.repository.UserRepository;
import tech.robd.jwt.util.JwtTokenUtil;

import java.util.HashSet;
import java.util.Set;

import com.fasterxml.jackson.databind.ObjectMapper;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@Nested
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AuthenticationIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private DomainRepository domainRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtTokenUtil jwtTokenUtil;

    private static final String TEST_DOMAIN = "testdomain";
    private static final String TEST_USERNAME = "testuser";
    private static final String TEST_PASSWORD = "password123";
    private static final String TEST_ROLE = "USER";
    private static final String ADMIN_ROLE = "ADMIN";

    @BeforeEach
    public void setup() {
        // Clean up existing test data
        userRepository.findByUsernameAndDomainName(TEST_USERNAME, TEST_DOMAIN)
                .ifPresent(user -> userRepository.delete(user));

        // Create test domain if it doesn't exist
        Domain domain = domainRepository.findByName(TEST_DOMAIN)
                .orElseGet(() -> {
                    Domain newDomain = new Domain();
                    newDomain.setName(TEST_DOMAIN);
                    newDomain.setDisplayName("Test Domain");
                    return domainRepository.save(newDomain);
                });

        // Create roles if they don't exist
        Role userRole = roleRepository.findByNameAndDomain(TEST_ROLE, domain)
                .orElseGet(() -> {
                    Role newRole = new Role();
                    newRole.setName(TEST_ROLE);
                    newRole.setDomain(domain);
                    return roleRepository.save(newRole);
                });

        Role adminRole = roleRepository.findByNameAndDomain(ADMIN_ROLE, domain)
                .orElseGet(() -> {
                    Role newRole = new Role();
                    newRole.setName(ADMIN_ROLE);
                    newRole.setDomain(domain);
                    return roleRepository.save(newRole);
                });

        // Create test user
        User testUser = new User();
        testUser.setUsername(TEST_USERNAME);
        testUser.setPassword(passwordEncoder.encode(TEST_PASSWORD));
        testUser.setEnabled(true);
        testUser.setDomain(domain);

        Set<Role> roles = new HashSet<>();
        roles.add(userRole);
        testUser.setRoles(roles);

        userRepository.save(testUser);
    }

    @Test
    public void testSuccessfulAuthentication() throws Exception {
        AuthRequest authRequest = new AuthRequest(TEST_USERNAME, TEST_PASSWORD, TEST_DOMAIN);

        MvcResult result = mockMvc.perform(post("/authenticate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(authRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").exists())
                .andReturn();

        String responseJson = result.getResponse().getContentAsString();
        String token = objectMapper.readTree(responseJson).get("token").asText();

        // Verify token is valid
        assertTrue(jwtTokenUtil.validateToken(token));
        assertEquals(TEST_USERNAME, jwtTokenUtil.getUsernameFromToken(token));
        assertTrue(jwtTokenUtil.getRolesFromToken(token).contains(TEST_ROLE));
    }

    @Test
    public void testAuthenticationWithInvalidCredentials() throws Exception {
        AuthRequest authRequest = new AuthRequest(TEST_USERNAME, "wrongpassword", TEST_DOMAIN);

        mockMvc.perform(post("/authenticate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(authRequest)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("Unauthorized: Invalid credentials"));
    }

    @Test
    public void testAuthenticationWithNonexistentUser() throws Exception {
        AuthRequest authRequest = new AuthRequest("nonexistentuser", TEST_PASSWORD, TEST_DOMAIN);

        mockMvc.perform(post("/authenticate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(authRequest)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    public void testAuthenticationWithoutDomain() throws Exception {
        AuthRequest authRequest = new AuthRequest(TEST_USERNAME, TEST_PASSWORD, null);

        mockMvc.perform(post("/authenticate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(authRequest)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    public void testProtectedEndpointWithValidToken() throws Exception {
        // First, get a valid token
        AuthRequest authRequest = new AuthRequest(TEST_USERNAME, TEST_PASSWORD, TEST_DOMAIN);

        MvcResult result = mockMvc.perform(post("/authenticate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(authRequest)))
                .andExpect(status().isOk())
                .andReturn();

        String responseJson = result.getResponse().getContentAsString();
        String token = objectMapper.readTree(responseJson).get("token").asText();

        // Now try to access a protected resource
        mockMvc.perform(get("/api/isUserValid")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk());
    }

    @Test
    public void testProtectedEndpointWithoutToken() throws Exception {
        mockMvc.perform(get("/api/isUserValid"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    public void testProtectedEndpointWithInvalidToken() throws Exception {
        mockMvc.perform(get("/api/isuservalid")
                        .header("Authorization", "Bearer invalidtoken"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    public void testAdminEndpointWithUserRole() throws Exception {
        // Get token for user with only USER role
        AuthRequest authRequest = new AuthRequest(TEST_USERNAME, TEST_PASSWORD, TEST_DOMAIN);

        MvcResult result = mockMvc.perform(post("/authenticate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(authRequest)))
                .andExpect(status().isOk())
                .andReturn();

        String responseJson = result.getResponse().getContentAsString();
        String token = objectMapper.readTree(responseJson).get("token").asText();

        // Try to access admin endpoint
        mockMvc.perform(get("/api/admin/users")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isForbidden());
    }
}