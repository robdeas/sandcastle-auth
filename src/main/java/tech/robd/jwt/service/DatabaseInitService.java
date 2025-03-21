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

import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;
import tech.robd.jwt.config.SecurityProperties;
import tech.robd.jwt.entity.Domain;
import tech.robd.jwt.entity.Role;
import tech.robd.jwt.entity.User;
import tech.robd.jwt.repository.DomainRepository;
import tech.robd.jwt.repository.RoleRepository;
import tech.robd.jwt.repository.UserRepository;
import tech.robd.jwt.util.TextUtils;

import java.util.*;

import static tech.robd.jwt.util.Constants.securityLogMarker;

@Service
public class DatabaseInitService {
    private static final Logger logger = LoggerFactory.getLogger(DatabaseInitService.class);

    private final RoleRepository roleRepository;
    private final UserRepository userRepository;
    private final DomainRepository domainRepository;
    private final PasswordEncoder passwordEncoder;
    private final SecurityProperties securityProperties;

    @Autowired
    public DatabaseInitService(
            RoleRepository roleRepository,
            UserRepository userRepository,
            DomainRepository domainRepository,
            PasswordEncoder passwordEncoder,
            SecurityProperties securityProperties) {
        this.roleRepository = roleRepository;
        this.userRepository = userRepository;
        this.domainRepository = domainRepository;
        this.passwordEncoder = passwordEncoder;
        this.securityProperties = securityProperties;
    }

    @PostConstruct
    @Transactional
    public void initialize() {
        logger.info("🔄 Initializing database with domains, roles, and users from configuration");

        // Create all domains
        Map<String, Domain> domainMap = createConfiguredDomains();

        // Create all roles
        Map<String, Role> roleMap = createConfiguredRoles(domainMap);

        // Create all users with their roles and domains
        createConfiguredUsers(roleMap, domainMap);

        logger.info("✅ Database initialization complete.");
    }

    private Map<String, Domain> createConfiguredDomains() {
        Map<String, Domain> domainMap = new HashMap<>();

        for (SecurityProperties.DomainConfig domainConfig : securityProperties.getDomains()) {
            String domainName = domainConfig.getName();
            if (StringUtils.hasText(domainName)) {
                Optional<Domain> existingDomain = domainRepository.findByName(domainName);
                if (existingDomain.isPresent()) {
                    logger.debug("Skipping existing domain: {}", domainName);
                    domainMap.put(domainName, existingDomain.get());
                    continue;
                }

                Domain domain = createDomain(domainConfig, domainName);
                domainRepository.save(domain);
                domainMap.put(domainName, domain);
                logger.info("🆕 Created new domain: {}", domainName);
            } else {
                logger.error("⚠️ Domain configuration error: Domain is defined without a name.");
            }
        }

        if (securityProperties.getSettings().isEnableDefaultDomain()) {
            addDefaultDomain(domainMap);
        }

        return domainMap;
    }

    private void addDefaultDomain(Map<String, Domain> domainMap) {
        String defaultDomainName = securityProperties.getSettings().getDefaultDomain();
        Domain retreivedDomain = domainMap.getOrDefault(securityProperties.getSettings().getDefaultDomain(), null);
        if (retreivedDomain == null) {
            SecurityProperties.DomainConfig defaultDomainConfig = new SecurityProperties.DomainConfig();
            defaultDomainConfig.setName(defaultDomainName);
            defaultDomainConfig.setDisplayName("Default Domain");

            Domain newDomain = createDomain(defaultDomainConfig, defaultDomainName);
            domainRepository.save(newDomain);
            domainMap.put(defaultDomainName, newDomain);
            logger.info("🔵 Created default domain: {}", defaultDomainName);
        }

    }

    private Domain createDomain(SecurityProperties.DomainConfig domainConfig, String domainName) {
        Domain domain = new Domain();
        domain.setName(domainName);
        domain.setDisplayName(StringUtils.hasText(domainConfig.getDisplayName()) ? domainConfig.getDisplayName() : domainName);

        if (StringUtils.hasText(domainConfig.getDefaultPin())) {
            domain.setDefaultPin(domainConfig.getDefaultPin());
            logger.warn(securityLogMarker, "⚠️ SECURITY ALERT: Default PIN (\"{}\") set from config for domain: {}", domainConfig.getDefaultPin(), domainName);
        } else if (securityProperties.getSettings().isUseSameRandomPinForWholeDomain()) {
            String randomPin = TextUtils.generateRandomHexString(securityProperties.getSettings().getRandomPinDigits());
            domain.setDefaultPin(randomPin);
            logger.warn(securityLogMarker, "⚠️ SECURITY ALERT: Generated random PIN  (\"{}\") for domain: {}", randomPin, domainName);
        }

        return domain;
    }

    private Map<String, Role> createConfiguredRoles(Map<String, Domain> domainMap) {
        Map<String, Role> roleMap = new HashMap<>();

        for (SecurityProperties.RoleConfig roleConfig : securityProperties.getRoles()) {
            String roleName = roleConfig.getName();
            String domainName = roleConfig.getDomain();
            Domain domain = domainMap.get(domainName);

            if (domain == null) {
                logger.warn("⚠️ Role creation failed: Domain {} not found for role {}", domainName, roleName);
                continue;
            }

            Optional<Role> existingRole = roleRepository.findByNameAndDomain(roleName, domain);
            if (existingRole.isPresent()) {
                logger.debug("Skipping existing role: {} in domain {}", roleName, domainName);
                roleMap.put(domainName + ":" + roleName, existingRole.get());
                continue;
            }

            Role role = new Role();
            role.setName(roleName);
            role.setDomain(domain);
            roleRepository.save(role);
            roleMap.put(domainName + ":" + roleName, role);

            logger.info("🆕 Created new role: {} in domain {}", roleName, domainName);
        }

        return roleMap;
    }

    private void createConfiguredUsers(Map<String, Role> roleMap, Map<String, Domain> domainMap) {
        for (SecurityProperties.UserConfig userConfig : securityProperties.getUsers()) {
            String username = userConfig.getUsername();
            String domainName = userConfig.getDomain();
            Domain domain = domainMap.get(domainName);

            if (domain == null) {
                logger.warn("⚠️ User creation failed: Domain {} not found for user {}", domainName, username);
                continue;
            }

            if (userRepository.existsByUsernameAndDomain(username, domain)) {
                logger.debug("Skipping existing user: {} in domain {}", username, domainName);
                continue;
            }

            User user = new User();
            user.setUsername(username);
            user.setDomain(domain);
            user.setPin(generateUserPin(userConfig, domain, username));

            String encodedPassword = encodeUserPassword(userConfig, user.getPin());
            user.setPassword(encodedPassword);
            user.setEnabled(userConfig.isEnabled());

            Set<Role> userRoles = assignUserRoles(userConfig, roleMap, domainName);
            user.setRoles(userRoles);

            userRepository.save(user);
            logger.info("🆕 Created new user: {} in domain {}", username, domainName);
        }
    }

    private String generateUserPin(SecurityProperties.UserConfig userConfig, Domain domain, String username) {
        if (StringUtils.hasText(userConfig.getPin())) {
            logger.warn(securityLogMarker, "⚠️ SECURITY ALERT: User PIN  (\"{}\") set from config for user: {} in domain: {}", userConfig.getPin(), username, domain.getName());
            return userConfig.getPin();
        } else if (StringUtils.hasText(domain.getDefaultPin())) {
            logger.warn(securityLogMarker, "⚠️ SECURITY ALERT: User PIN (\"{}\") set by default from domain config for user: {} in domain: {}", domain.getDefaultPin(), username, domain.getName());
            return domain.getDefaultPin();
        } else if (!securityProperties.getSettings().isUseSameRandomPinForWholeDomain()) {
            String generatedPin = TextUtils.generateRandomHexString(securityProperties.getSettings().getRandomPinDigits());
            logger.warn(securityLogMarker, "⚠️ SECURITY ALERT: Generated random PIN (\"{}\") for user: {} in domain: {} ", generatedPin, username, domain.getName());
            return generatedPin;
        }
        return "";
    }

    private String encodeUserPassword(SecurityProperties.UserConfig userConfig, String pin) {
        StringBuilder password = new StringBuilder(userConfig.getPassword());
        if (securityProperties.getSettings().getRandomPinDigits() > 0) {
            password.append(securityProperties.getSettings().getPasswordPartSeperator()).append(pin);
        }
        return passwordEncoder.encode(password.toString());
    }

    private Set<Role> assignUserRoles(SecurityProperties.UserConfig userConfig, Map<String, Role> roleMap, String domainName) {
        Set<Role> userRoles = new HashSet<>();
        for (String roleName : userConfig.getRoles()) {
            Role role = roleMap.get(domainName + ":" + roleName);
            if (role != null) {
                userRoles.add(role);
            } else {
                logger.warn("⚠️ Role {} not found for user in domain {}", roleName, domainName);
            }
        }
        return userRoles;
    }
}
