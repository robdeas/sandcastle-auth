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
package tech.robd.jwt.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import tech.robd.jwt.domainsecurity.DomainUser;
import tech.robd.jwt.entity.Domain;
import tech.robd.jwt.entity.User;
import tech.robd.jwt.repository.DomainRepository;
import tech.robd.jwt.repository.UserRepository;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    private static final Logger logger = LoggerFactory.getLogger(CustomUserDetailsService.class);

    private final UserRepository userRepository;
    private final DomainRepository domainRepository;

    @Autowired
    public CustomUserDetailsService(UserRepository userRepository, DomainRepository domainRepository) {
        this.userRepository = userRepository;
        this.domainRepository = domainRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        logger.info("🔍 Attempting to load user by username: {}", username);

        Optional<User> userOpt = userRepository.findByUsername(username);

        if (userOpt.isEmpty()) {
            logger.warn("❌ User not found: {}", username);
            throw new UsernameNotFoundException("User not found: " + username);
        }

        User user = userOpt.get();
        logger.debug("✅ User found: {} (ID: {})", username, user.getId());

        logger.debug("🔎 Fetching domain for user: {}", username);
        Optional<Domain> domainOpt = domainRepository.findById(user.getDomain().getId());

        if (domainOpt.isEmpty()) {
            logger.warn("❌ Domain not found for user: {}", username);
            throw new UsernameNotFoundException("Domain not found for user: " + username);
        }

        Domain domain = domainOpt.get();
        logger.debug("✅ Domain found for user '{}': {}", username, domain.getName());

        // Convert roles to authorities
        List<GrantedAuthority> authorities = new ArrayList<>();
        user.getRoles().forEach(role -> {
            String roleName = "ROLE_" + role.getName();
            authorities.add(new SimpleGrantedAuthority(roleName));
            logger.debug("🔑 Assigned role '{}' to user '{}'", roleName, username);
        });

        if (authorities.isEmpty()) {
            logger.warn("⚠️ User '{}' has no assigned roles!", username);
        }

        logger.info("✅ Successfully loaded user: {}, Roles: {}, Domain: {}", username, authorities, domain.getName());

        return new DomainUser(user.getUsername(), user.getPassword(), authorities, domain.getName());
    }
}
