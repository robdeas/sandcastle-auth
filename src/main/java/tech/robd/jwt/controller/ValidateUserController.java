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

import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import tech.robd.jwt.config.SecurityProperties;
import tech.robd.jwt.service.UserService;
import tech.robd.jwt.util.JwtTokenUtil;

import java.security.Principal;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class ValidateUserController {
    private static final Logger logger = LoggerFactory.getLogger(ValidateUserController.class);

    private final UserService userService;
    private final JwtTokenUtil jwtTokenUtil;
    private final SecurityProperties securityProperties;

    @Autowired
    public ValidateUserController(UserService userService, JwtTokenUtil jwtTokenUtil, SecurityProperties securityProperties) {
        this.userService = userService;
        this.jwtTokenUtil = jwtTokenUtil;
        this.securityProperties = securityProperties;
    }

    // 🔐 Logs and validates authenticated users
    @GetMapping("/isUserValid")
    public ResponseEntity<Map<String, Object>> isUserValid(HttpServletRequest request, Principal principal) {
        logger.info("🔍 Validating user session for: {}", principal.getName());

        String authHeader = request.getHeader("Authorization");
        String token = null;
        Map<String, Object> response = new HashMap<>();

        response.put("isValid", true);
        response.put("username", principal.getName());
        response.put("message", "User is authenticated and valid.");
        response.put("version", "1");

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            token = authHeader.substring(7); // Remove "Bearer " prefix
            logger.debug("📜 Extracted JWT token from Authorization header");

            try {
                // Extract claims from token
                String usernameFromToken = jwtTokenUtil.parseUserNameFromToken(token).orElse("* NO USERNAME IN TOKEN *");
                String domainFromToken = jwtTokenUtil.getDomainFromToken(token).orElse("* NO DOMAIN IN TOKEN *");
                Collection<String> rolesFromToken = jwtTokenUtil.getRolesFromToken(token);

                response.put("usernameFromToken", usernameFromToken);
                response.put("domain", domainFromToken);

                int roleNum = 1;
                for (String roleFromToken : rolesFromToken) {
                    response.put("role" + roleNum, roleFromToken);
                    roleNum++;
                }

                logger.info("✅ Token validated for user '{}'. Domain: '{}', Roles: {}", usernameFromToken, domainFromToken, rolesFromToken);

            } catch (Exception e) {
                logger.error("❌ Failed to parse token: {}", e.getMessage(), e);
                response.put("error", "Failed to parse token: " + e.getMessage());
            }
        } else {
            logger.warn("⚠️ Authorization header is missing or invalid.");
            response.put("error", "Authorization header is missing or invalid");
        }

        return ResponseEntity.ok(response);
    }

    // 🔐 Logs authorization checks for local admin users
    @GetMapping("/isLocalAdmin")
    @PreAuthorize("@domainChecker.isInAuthDomain(#domain) and hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> isUserAdmin(Principal principal) {
        logger.info("🔐 Checking if user '{}' is a local authentication admin.", principal.getName());

        Map<String, Object> response = new HashMap<>();
        response.put("isValid", true);
        response.put("username", principal.getName());
        response.put("message", "User is an authentication domain admin user.");
        response.put("version", "1");

        logger.info("✅ User '{}' is confirmed as an authentication admin.", principal.getName());
        return ResponseEntity.ok(response);
    }
}
