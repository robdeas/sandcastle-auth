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
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import tech.robd.jwt.entity.Domain;
import tech.robd.jwt.entity.User;
import tech.robd.jwt.repository.DomainRepository;
import tech.robd.jwt.repository.UserRepository;

import java.util.Optional;

@Service
public class UserService {
    private static final Logger logger = LoggerFactory.getLogger(UserService.class);

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final DomainRepository domainRepository;

    @Autowired
    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder,
                       DomainRepository domainRepository) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.domainRepository = domainRepository;
    }

    /**
     * Find a user by username and domain.
     *
     * @param username the username
     * @param domainName the domain name
     * @return Optional containing user if found
     */
    public Optional<User> findByUsername(String username, String domainName) {
        logger.info("🔍 Searching for user '{}', domain: '{}'", username, domainName);
        Optional<User> userOpt = userRepository.findByUsernameAndDomainName(username, domainName);

        if (userOpt.isPresent()) {
            logger.debug("✅ User found: '{}', domain: '{}'", username, domainName);
        } else {
            logger.warn("❌ User not found: '{}', domain: '{}'", username, domainName);
        }

        return userOpt;
    }

    /**
     * Validate user credentials.
     *
     * @param username the username
     * @param rawPassword the raw password (plaintext)
     * @param domainName the domain name
     * @return true if credentials are valid, false otherwise
     */
    public boolean validateCredentials(String username, String rawPassword, String domainName) {
        logger.info("🔑 Validating credentials for user '{}', domain: '{}'", username, domainName);

        Optional<User> userOpt = userRepository.findByUsernameAndDomainName(username, domainName);

        if (userOpt.isEmpty()) {
            logger.warn("❌ Validation failed: User '{}' not found in domain '{}'", username, domainName);
            return false;
        }

        User user = userOpt.get();

        if (!user.isEnabled()) {
            logger.warn("⚠️ User '{}' is disabled in domain '{}'", username, domainName);
            return false;
        }

        boolean passwordMatches = passwordEncoder.matches(rawPassword, user.getPassword());

        if (!passwordMatches) {
            logger.warn("🚫 Incorrect password for user '{}', domain '{}'", username, domainName);
            return false;
        }

        logger.info("✅ Credentials validated successfully for user '{}', domain '{}'", username, domainName);
        return true;
    }

    /**
     * Create a new user and associate it with a domain.
     *
     * @param username the username
     * @param rawPassword the raw password (will be encoded)
     * @param domainName the domain name
     * @return Optional containing the created user
     */
    public Optional<User> createUser(String username, String rawPassword, String domainName) {
        logger.info("🆕 Creating new user: '{}', domain: '{}'", username, domainName);

        if (userRepository.findByUsernameAndDomainName(username, domainName).isPresent()) {
            logger.warn("⚠️ Cannot create user: '{}' already exists in domain '{}'", username, domainName);
            return Optional.empty();
        }

        Optional<Domain> domainOpt = domainRepository.findByName(domainName);
        if (domainOpt.isEmpty()) {
            logger.warn("❌ Domain '{}' not found. Cannot create user '{}'", domainName, username);
            return Optional.empty();
        }

        Domain domain = domainOpt.get();
        String encodedPassword = passwordEncoder.encode(rawPassword);

        User newUser = new User();
        newUser.setUsername(username);
        newUser.setPassword(encodedPassword);
        newUser.setDomain(domain);
        newUser.setEnabled(true); // Set default enabled status

        User savedUser = userRepository.save(newUser);
        logger.info("✅ User '{}' successfully created in domain '{}'", username, domainName);

        return Optional.of(savedUser);
    }
}
