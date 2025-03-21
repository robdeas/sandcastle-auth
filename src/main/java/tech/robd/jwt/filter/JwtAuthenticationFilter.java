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
package tech.robd.jwt.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import tech.robd.jwt.service.CustomUserDetailsService;
import tech.robd.jwt.util.JwtTokenUtil;

import java.io.IOException;
import java.util.Collection;
import java.util.stream.Collectors;

// We register this bean manually so don't want @Component here
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    private final JwtTokenUtil jwtTokenUtil;
    private final CustomUserDetailsService userDetailsService;

    @Autowired
    public JwtAuthenticationFilter(JwtTokenUtil jwtTokenUtil, CustomUserDetailsService userDetailsService) {
        this.jwtTokenUtil = jwtTokenUtil;
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain)
            throws ServletException, IOException {

        String requestURI = request.getRequestURI();
        String jwt = getJwtFromRequest(request);

        if (StringUtils.hasText(jwt)) {
            logger.info("🔐 JWT detected in request for URI: {}", requestURI);

            if (jwtTokenUtil.validateToken(jwt)) {
                logger.debug("✅ JWT token is valid for request URI: {}", requestURI);

                try {
                    String username = jwtTokenUtil.getUsernameFromToken(jwt);
                    Collection<String> roles = jwtTokenUtil.getRolesFromToken(jwt);

                    logger.info("✅ Authenticated user '{}', Roles: {}, Request URI: {}", username, roles, requestURI);

                    // Convert roles to authorities
                    var authorities = roles.stream()
                            .map(role -> new SimpleGrantedAuthority("ROLE_" + role.toUpperCase()))
                            .collect(Collectors.toList());

                    logger.debug("🔑 User '{}' granted authorities: {}", username, authorities);

                    UserDetails userDetails = userDetailsService.loadUserByUsername(username);

                    UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                            userDetails, null, userDetails.getAuthorities());

                    authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                    SecurityContextHolder.getContext().setAuthentication(authentication);
                    logger.debug("✅ Security context updated for '{}'", username);
                } catch (Exception e) {
                    logger.error("❌ Error extracting claims from JWT: {}", e.getMessage(), e);
                }

            } else {
                logger.warn("⚠️ Invalid JWT token received for request URI: {}", requestURI);
            }
        } else {
            logger.debug("🚫 No JWT token found in request for URI: {}", requestURI);
        }

        filterChain.doFilter(request, response);
    }

    private String getJwtFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            logger.debug("📜 Extracted Bearer token from Authorization header.");
            return bearerToken.substring(7);
        }
        logger.warn("⚠️ No valid Bearer token found in Authorization header.");
        return null;
    }
}
