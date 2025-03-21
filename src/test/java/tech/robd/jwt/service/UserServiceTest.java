
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
package tech.robd.jwt.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.InjectMocks;
import org.mockito.MockitoAnnotations;
import tech.robd.jwt.entity.Domain;
import tech.robd.jwt.entity.User;
import tech.robd.jwt.repository.DomainRepository;
import tech.robd.jwt.repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.*;

class UserServiceTest {

    @Mock
    UserRepository userRepository;

    @Mock
    DomainRepository domainRepository;

    @Mock
    PasswordEncoder passwordEncoder;

    @InjectMocks
    UserService userService; // System under test

    @BeforeEach
    void setup() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void testValidateCredentials_UserNotFound() {
        given(userRepository.findByUsernameAndDomainName("foo", "bar"))
                .willReturn(Optional.empty());

        boolean result = userService.validateCredentials("foo", "password", "bar");
        assertFalse(result);
        verify(userRepository).findByUsernameAndDomainName("foo", "bar");
    }

    @Test
    void testValidateCredentials_UserDisabled() {
        User disabledUser = new User();
        disabledUser.setEnabled(false);
        given(userRepository.findByUsernameAndDomainName("alice", "domain"))
                .willReturn(Optional.of(disabledUser));

        boolean result = userService.validateCredentials("alice", "pw", "domain");
        assertFalse(result);
    }

    @Test
    void testValidateCredentials_InvalidPassword() {
        User enabledUser = new User();
        enabledUser.setEnabled(true);
        enabledUser.setPassword("hashedPw");

        given(userRepository.findByUsernameAndDomainName("bob", "domain"))
                .willReturn(Optional.of(enabledUser));

        // passwordEncoder.matches("rawPw","hashedPw") = false
        given(passwordEncoder.matches("rawPw", "hashedPw")).willReturn(false);

        boolean result = userService.validateCredentials("bob", "rawPw", "domain");
        assertFalse(result);
    }

    @Test
    void testValidateCredentials_Success() {
        User enabledUser = new User();
        enabledUser.setEnabled(true);
        enabledUser.setPassword("hashedPw");

        given(userRepository.findByUsernameAndDomainName("alice2", "domain"))
                .willReturn(Optional.of(enabledUser));

        given(passwordEncoder.matches("alice2Pw", "hashedPw")).willReturn(true);

        boolean result = userService.validateCredentials("alice2", "alice2Pw", "domain");
        assertTrue(result);
    }

    @Test
    void testCreateUser_DomainNotFound() {
        given(domainRepository.findByName("missingDomain"))
                .willReturn(Optional.empty());

        Optional<User> createdUser = userService.createUser("newUser", "secret", "missingDomain");
        assertTrue(createdUser.isEmpty());
    }

    @Test
    void testCreateUser_UserExists() {
        Domain domain = new Domain();
        domain.setName("domain");

        User existingUser = new User();
        existingUser.setUsername("existingUser");

        given(userRepository.findByUsernameAndDomainName("existingUser", "domain"))
                .willReturn(Optional.of(existingUser));

        Optional<User> result = userService.createUser("existingUser", "pw", "domain");
        assertTrue(result.isEmpty());
    }

    @Test
    void testCreateUser_Success() {
        Domain domain = new Domain();
        domain.setName("domain");
        given(domainRepository.findByName("domain"))
                .willReturn(Optional.of(domain));

        given(userRepository.findByUsernameAndDomainName("newUser", "domain"))
                .willReturn(Optional.empty());

        given(passwordEncoder.encode("secretPw")).willReturn("encodedPw");

        User savedUser = new User();
        savedUser.setUsername("newUser");
        savedUser.setPassword("encodedPw");
        savedUser.setDomain(domain);
        savedUser.setEnabled(true);

        given(userRepository.save(any(User.class))).willReturn(savedUser);

        Optional<User> result = userService.createUser("newUser", "secretPw", "domain");
        assertTrue(result.isPresent());
        assertEquals("newUser", result.get().getUsername());
        assertEquals("encodedPw", result.get().getPassword());
        assertEquals(domain, result.get().getDomain());
        verify(userRepository).save(any(User.class));
    }
}
