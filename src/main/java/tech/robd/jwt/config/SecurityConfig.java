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
package tech.robd.jwt.config;

import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import tech.robd.jwt.filter.JwtAuthenticationFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import tech.robd.jwt.service.CustomUserDetailsService;
import tech.robd.jwt.util.JwtTokenUtil;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter(
            JwtTokenUtil jwtTokenUtil,
            CustomUserDetailsService userDetailsService
    ) {
        return new JwtAuthenticationFilter(jwtTokenUtil, userDetailsService);
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, JwtAuthenticationFilter jwtAuthenticationFilter) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(new AntPathRequestMatcher("/authenticate")).permitAll()
                        .requestMatchers(new AntPathRequestMatcher("/api/isUserValid/**")).hasAnyRole("USER", "ADMIN")
                        .requestMatchers(new AntPathRequestMatcher("/api/isLocalAdmin/**")).hasRole("ADMIN")
                        .requestMatchers(new AntPathRequestMatcher("/api/admin/**")).hasRole("ADMIN")
                        .requestMatchers(new AntPathRequestMatcher("/api/rest/users/**")).hasRole("ADMIN")
                        .requestMatchers(new AntPathRequestMatcher("/api/rest/roles/**")).hasRole("ADMIN")
                        .requestMatchers(new AntPathRequestMatcher("/api/rest/domains/**")).hasRole("ADMIN")
                        .requestMatchers(new AntPathRequestMatcher("/h2-console/**")).denyAll()
                        .anyRequest().authenticated()
                )
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .httpBasic(Customizer.withDefaults());

        return http.build();
    }

}
