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
package tech.robd.jwt.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import tech.robd.jwt.config.SecurityProperties;
import tech.robd.jwt.entity.Domain;
import tech.robd.jwt.entity.Role;
import tech.robd.jwt.entity.User;
import tech.robd.jwt.service.UserService;
import tech.robd.jwt.util.JwtTokenUtil;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
@WebMvcTest(AuthController.class)
@AutoConfigureMockMvc(addFilters = false) // Disable security filters for testing
@TestPropertySource(properties = {
        "app.username1.regex=^(user1|user2|user3)$",
        "app.username1.role=user",
        "app.username2.regex=^(admin1)$",
        "app.username2.role=admin",
        "app.passwordPrefix=",
        "app.passwordSuffix=pass"
})
public class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockBean
    private UserService userService; // Mock UserService

    @MockBean
    private JwtTokenUtil jwtTokenUtil; // Mock JwtTokenUtil

    @MockBean
    private SecurityProperties securityProperties; // Mock SecurityProperties

    @BeforeEach
    void setup() {
        SecurityProperties.SettingsConfig settings = new SecurityProperties.SettingsConfig();
        settings.setSingleDomain(false); // Set test-specific values
        settings.setDefaultDomain("default");

        when(securityProperties.getSettings()).thenReturn(settings);
    }

    @Test
    void testMissingUsername() throws Exception {
        AuthRequest request = new AuthRequest("", "anyPassword", "default");

        mockMvc.perform(post("/authenticate")
                        .contentType("application/json")
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("Unauthorized: Username and domain are required"));
    }

    @Test
    void testInvalidUsername() throws Exception {
        AuthRequest request = new AuthRequest("invalidUser", "invalidUserpass", "default");

        when(userService.validateCredentials(any(), any(), any())).thenReturn(false);

        mockMvc.perform(post("/authenticate")
                        .contentType("application/json")
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("Unauthorized: Invalid credentials"));
    }

    @Test
    void testInvalidPassword() throws Exception {
        AuthRequest request = new AuthRequest("user1", "wrongPassword", "default");

        when(userService.validateCredentials(eq("user1"), eq("wrongPassword"), any())).thenReturn(false);

        mockMvc.perform(post("/authenticate")
                        .contentType("application/json")
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("Unauthorized: Invalid credentials"));
    }

    @Test
    void testSuccessfulAuthentication() throws Exception {
        AuthRequest request = new AuthRequest("user1", "user1pass", "default");
        User mockUser = new User();
        mockUser.setUsername("user1");
        mockUser.setPassword("user1pass");
        Domain mockDomain = new Domain();
        mockDomain.setName("default");
        mockUser.setDomain(mockDomain); // Ensure Domain is set
        //  Add a role
        Role userRole = new Role();
        userRole.setName("USER");

        Set<Role> roles = new HashSet<>();
        roles.add(userRole);
        mockUser.setRoles(roles); // Fix: set roles
        // Mock valid authentication
        when(userService.validateCredentials(eq("user1"), eq("user1pass"), eq("default"))).thenReturn(true);
        when(userService.findByUsername(eq("user1"), eq("default")))
                .thenReturn(Optional.of(mockUser));

        // Mock JWT token generation
        when(jwtTokenUtil.generateToken(eq("user1"), any(), eq("default"), anyBoolean())).thenReturn("mocked-jwt-token");

        mockMvc.perform(post("/authenticate")
                        .contentType("application/json")
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").value("mocked-jwt-token"));
    }
}
