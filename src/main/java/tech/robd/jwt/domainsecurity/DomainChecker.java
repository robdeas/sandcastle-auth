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
package tech.robd.jwt.domainsecurity;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import tech.robd.jwt.config.SecurityProperties;
import tech.robd.jwt.entity.Domain;

@Component("domainChecker")
public class DomainChecker {

    private static final Logger logger = LoggerFactory.getLogger(DomainChecker.class);

    private final SecurityProperties securityProperties;

    @Autowired
    public DomainChecker(SecurityProperties securityProperties) {
        this.securityProperties = securityProperties;
    }

    public boolean isInDomain(String expectedDomain) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null) {
            logger.warn("isInDomain check failed: No authentication found in security context");
            return false;
        }

        if (!(authentication.getPrincipal() instanceof DomainUser user)) {
            logger.warn("isInDomain check failed: Principal is not of type DomainUser. Found: {}", authentication.getPrincipal().getClass());
            return false;
        }

        boolean matches = user.getDomain().equals(expectedDomain);
        logger.debug("Checking if user is in expected domain: Expected={}, UserDomain={}, Match={}",
                expectedDomain, user.getDomain(), matches);

        return matches;
    }

    public boolean isInAuthDomain(Domain domain) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null) {
            logger.warn("isInAuthDomain check failed: No authentication found in security context");
            return false;
        }


        if (!(authentication.getPrincipal() instanceof DomainUser user)) {
            logger.warn("isInAuthDomain check failed: Principal is not of type DomainUser. Found: {}", authentication.getPrincipal().getClass());
            return false;
        }

        String expectedAuthDomain = securityProperties.getSettings().getAuthAdminDomainName();
        boolean matches = user.getDomain().equals(expectedAuthDomain);

        logger.debug("Checking if user is in Auth Domain: ExpectedAuthDomain={}, UserDomain={}, Match={}",
                expectedAuthDomain, user.getDomain(), matches);

        return matches;
    }
}
