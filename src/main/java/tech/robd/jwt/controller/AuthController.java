/*
 * Copyright (c) 2025 Robert Deas
 * This file is part of: sandcastle-auth - An Authentication server for testing and learning
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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;
import tech.robd.jwt.config.SecurityProperties;
import tech.robd.jwt.entity.Role;
import tech.robd.jwt.entity.User;
import tech.robd.jwt.service.UserService;
import tech.robd.jwt.util.JwtTokenUtil;

import java.util.Optional;
import java.util.stream.Collectors;

@RestController
public class AuthController {
    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    private final UserService userService;
    private final JwtTokenUtil jwtTokenUtil;
    private final SecurityProperties securityProperties;

    @Autowired
    public AuthController(UserService userService, JwtTokenUtil jwtTokenUtil, SecurityProperties securityProperties) {
        this.userService = userService;
        this.jwtTokenUtil = jwtTokenUtil;
        this.securityProperties = securityProperties;
    }

    @PostMapping("/authenticate")
    public ResponseEntity<?> authenticate(@RequestBody AuthRequest authRequest) {
        logger.info("🔐 Authentication request received for username: {}", authRequest.username());

        // Check if username or domain is missing
        if (!StringUtils.hasText(authRequest.username()) || !StringUtils.hasText(authRequest.domain())) {
            logger.warn("⚠️ Authentication failed: Missing username or domain");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ErrorResponse("Unauthorized: Username and domain are required"));
        }

        // Check if the password is missing
        if (!StringUtils.hasText(authRequest.password())) {
            logger.warn("⚠️ Authentication failed: Password is missing for user '{}'", authRequest.username());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ErrorResponse("Unauthorized: Password is required"));
        }

        // Determine domain name
        String domain = resolveDomain(authRequest.domain());

        logger.debug("🔍 Authenticating user '{}' in domain '{}'", authRequest.username(), domain);

        // Validate credentials
        try {
            boolean isValid = userService.validateCredentials(authRequest.username(), authRequest.password(), domain);
            if (!isValid) {
                logger.warn("❌ Authentication failed for user '{}' in domain '{}'", authRequest.username(), domain);
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new ErrorResponse("Unauthorized: Invalid credentials"));
            }
        } catch (Exception e) {
            logger.error("❌ Unexpected error during authentication for user '{}': {}", authRequest.username(), e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(new ErrorResponse("Internal Server Error"));
        }


        // Fetch user to get roles
        Optional<User> userOpt = userService.findByUsername(authRequest.username(), domain);

        if (userOpt.isEmpty()) {
            logger.error("❌ Authentication failed: User '{}' found during credential check but missing during retrieval", authRequest.username());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ErrorResponse("Error fetching user details"));
        }

        User user = userOpt.get();

        // Extract role names
        var roles = user.getRoles().stream()
                .map(Role::getName)
                .collect(Collectors.toList());

        logger.debug("✅ User '{}' roles: {}", user.getUsername(), roles);

        if (roles.isEmpty()) {
            logger.warn("❌ User '{}' has no roles assigned. Authentication denied.", user.getUsername());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ErrorResponse("Unauthorized: User has no assigned roles"));
        }
        // Generate a token
        String token = jwtTokenUtil.generateToken(user.getUsername(), roles, domain, !securityProperties.getSettings().isSingleDomain());

        logger.info("✅ Authentication successful for user '{}'. Token issued.", user.getUsername());
        return ResponseEntity.ok(new AuthResponse(token));
    }

    private String resolveDomain(String inputDomain) {
        if (securityProperties.getSettings().isSingleDomain()) {
            logger.debug("🌍 Single-domain mode: Overriding input domain with '{}'", securityProperties.getSettings().getDefaultDomain());
            return securityProperties.getSettings().getDefaultDomain();
        } else if (securityProperties.getSettings().isEnableDefaultDomain() && !StringUtils.hasText(inputDomain)) {
            logger.debug("🌍 Using default domain as no domain was provided.");
            return securityProperties.getSettings().getDefaultDomain();
        }
        return inputDomain.toLowerCase();
    }
}
