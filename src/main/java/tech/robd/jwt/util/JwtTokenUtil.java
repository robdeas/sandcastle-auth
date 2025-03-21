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

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

@Component
public class JwtTokenUtil {
    private static final Logger logger = LoggerFactory.getLogger(JwtTokenUtil.class);

    @Value("${jwt.token.validity:86400}")
    private long jwtTokenValidity; // Default: 24 hours

    private final SecretKey secretKey;

    public JwtTokenUtil() {
        this.secretKey = loadSecretKeyFromFile();
    }

    private SecretKey loadSecretKeyFromFile() {
        try {
            Path keyPath = Paths.get("config", "jwt-key.txt");

            if (!Files.exists(keyPath)) {
                logger.error("⚠️ JWT secret key file not found: {}", keyPath);
                throw new RuntimeException("JWT secret key file is missing!");
            }

            var lines = Files.readAllLines(keyPath);
            var startIndex = !lines.isEmpty() && lines.getFirst().trim().startsWith("#") ? 1 : 0;

            var keyContent = lines.subList(startIndex, lines.size()).stream()
                    .map(line -> line.replaceAll("\\s+", ""))
                    .collect(Collectors.joining());

            if (keyContent.isEmpty()) {
                logger.error("❌ JWT secret key file is empty at path: {}", keyPath);
                throw new RuntimeException("JWT secret key file is empty!");
            }

            logger.info("✅ JWT secret key loaded successfully from {}", keyPath);
            return Keys.hmacShaKeyFor(Decoders.BASE64.decode(keyContent));
        } catch (IOException e) {
            logger.error("❌ Failed to load JWT secret key from file", e);
            throw new RuntimeException("Failed to load JWT secret key", e);
        }
    }

    public String generateToken(String username, Collection<String> roles, String domain, boolean includeDomain) {
        logger.info("🔐 Generating JWT token for user: {}, domain: {}", username, domain);

        Map<String, Object> claims = new HashMap<>();
        claims.put("roles", Objects.requireNonNullElse(roles, Collections.emptyList()));
        claims.put("domain", Objects.requireNonNullElse(domain, "unknown"));

        String token = Jwts.builder()
                .setClaims(claims)
                .setSubject(username)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + jwtTokenValidity * 1000))
                .signWith(secretKey)
                .compact();

        logger.debug("✅ Token generated successfully for user: {}", username);
        return token;
    }

    public String getUsernameFromToken(String token) {
        logger.debug("🔎 Extracting username from JWT token...");
        return getClaimFromToken(token, Claims::getSubject);
    }

    @SuppressWarnings("unchecked")
    public Collection<String> getRolesFromToken(String token) {
        Claims claims = getAllClaimsFromToken(token);
        Object rolesClaim = claims.get("roles");

        logger.debug("🔎 Extracted roles claim from token: {}", rolesClaim);

        if (rolesClaim instanceof String rolesString) {
            // If roles are stored as a comma-separated string
            return Arrays.stream(rolesString.split(","))
                    .map(String::trim)
                    .collect(Collectors.toList());
        } else if (rolesClaim instanceof Collection<?> rolesList) {
            // If roles are stored as a list, ensure they are Strings
            return rolesList.stream()
                    .map(Object::toString)
                    .collect(Collectors.toList());
        } else {
            logger.warn("⚠️ Roles claim has an unexpected format: {}", rolesClaim);
        }

        return Collections.emptyList();
    }

    public Optional<String> getDomainFromToken(String token) {
        try {
            Claims claims = getAllClaimsFromToken(token);
            String domain = claims.get("domain", String.class);
            logger.debug("🔎 Extracted domain from token: {}", domain);
            return Optional.ofNullable(domain);
        } catch (Exception e) {
            logger.error("❌ Failed to extract domain from JWT token", e);
            return Optional.empty();
        }
    }

    public Date getExpirationDateFromToken(String token) {
        return getClaimFromToken(token, Claims::getExpiration);
    }

    public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
        Claims claims = getAllClaimsFromToken(token);
        return claimsResolver.apply(claims);
    }

    private Claims getAllClaimsFromToken(String token) {
        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(secretKey)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
            logger.debug("✅ Successfully extracted claims from JWT token.");
            return claims;
        } catch (Exception e) {
            logger.error("❌ Failed to parse JWT token", e);
            throw new RuntimeException("Invalid JWT token", e);
        }
    }

    public Optional<String> parseUserNameFromToken(String token) {
        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(secretKey)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
            logger.debug("✅ Extracted username from token: {}", claims.getSubject());
            return Optional.ofNullable(claims.getSubject());
        } catch (Exception e) {
            logger.error("❌ Failed to extract username from JWT token", e);
            return Optional.empty();
        }
    }

    public Boolean validateToken(String token) {
        try {
            logger.debug("🔍 Validating JWT token...");
            boolean isValid = !isTokenExpired(token);
            if (isValid) {
                logger.debug("✅ JWT token is valid.");
            } else {
                logger.warn("⚠️ JWT token has expired.");
            }
            return isValid;
        } catch (Exception e) {
            logger.error("❌ JWT token validation error", e);
            return false;
        }
    }

    private Boolean isTokenExpired(String token) {
        try {
            Date expiration = getExpirationDateFromToken(token);
            boolean expired = expiration.before(new Date());
            logger.debug("🔎 Token expiration check: Expiration={}, Expired={}", expiration, expired);
            return expired;
        } catch (Exception e) {
            logger.error("❌ Failed to check token expiration", e);
            return true;
        }
    }
}
