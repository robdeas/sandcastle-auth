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

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.ArrayList;
import java.util.List;

@Configuration
@ConfigurationProperties(prefix = "app.security")
public class SecurityProperties {

    private List<DomainConfig> domains = new ArrayList<>();
    private List<RoleConfig> roles = new ArrayList<>();
    private List<UserConfig> users = new ArrayList<>();
    private SettingsConfig settings = new SettingsConfig();

    public List<DomainConfig> getDomains() {
        return domains;
    }

    public void setDomains(List<DomainConfig> domains) {
        this.domains = domains;
    }


    public List<RoleConfig> getRoles() {
        return roles;
    }

    public void setRoles(List<RoleConfig> roles) {
        this.roles = roles;
    }

    public List<UserConfig> getUsers() {
        return users;
    }

    public void setUsers(List<UserConfig> users) {
        this.users = users;
    }

    public SettingsConfig getSettings() {
        return settings;
    }

    public void setSettings(SettingsConfig settings) {
        this.settings = settings;
    }

    public static class DomainConfig {
        private String name;
        private String displayName;
        private String defaultPin;

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public String getDisplayName() {
            return displayName;
        }

        public void setDisplayName(String displayName) {
            this.displayName = displayName;
        }

        public String getDefaultPin() {
            return defaultPin;
        }

        public void setDefaultPin(String defaultPin) {
            this.defaultPin = defaultPin;
        }
    }


    public static class RoleConfig {
        private String name;
        private String description;
        private String domain;

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public String getDescription() {
            return description;
        }

        public void setDescription(String description) {
            this.description = description;
        }

        public String getDomain() {
            return domain;
        }

        public void setDomain(String domain) {
            this.domain = domain;
        }
    }


    public static class UserConfig {
        private String username;
        private String password;
        private String domain;
        private String pin;
        private boolean enabled = true;
        private List<String> roles = new ArrayList<>();

        public String getUsername() {
            return username;
        }

        public void setUsername(String username) {
            this.username = username;
        }

        public String getPassword() {
            return password;
        }

        public void setPassword(String password) {
            this.password = password;
        }

        public String getDomain() {
            return domain;
        }

        public void setDomain(String domain) {
            this.domain = domain;
        }

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public List<String> getRoles() {
            return roles;
        }

        public void setRoles(List<String> roles) {
            this.roles = roles;
        }

        public String getPin() {
            return pin;
        }

        public void setPin(String pin) {
            this.pin = pin;
        }
    }

    public static class SettingsConfig {
        private int randomPinDigits;
        private boolean useSameRandomPinForWholeDomain;
        private String defaultDomain;
        private boolean enableDefaultDomain;
        private boolean singleDomain;
        private String passwordPartSeperator;
        private String authAdminDomainName;

        public int getRandomPinDigits() {
            return randomPinDigits;
        }

        public void setRandomPinDigits(int randomPinDigits) {
            this.randomPinDigits = randomPinDigits;
        }

        public boolean isUseSameRandomPinForWholeDomain() {
            return useSameRandomPinForWholeDomain;
        }

        public void setUseSameRandomPinForWholeDomain(boolean useSameRandomPinForWholeDomain) {
            this.useSameRandomPinForWholeDomain = useSameRandomPinForWholeDomain;
        }

        public String getDefaultDomain() {
            return defaultDomain;
        }

        public void setDefaultDomain(String defaultDomain) {
            this.defaultDomain = defaultDomain;
        }

        public boolean isEnableDefaultDomain() {
            return enableDefaultDomain;
        }

        public void setEnableDefaultDomain(boolean enableDefaultDomain) {
            this.enableDefaultDomain = enableDefaultDomain;
        }

        public boolean isSingleDomain() {
            return singleDomain;
        }

        public void setSingleDomain(boolean singleDomain) {
            this.singleDomain = singleDomain;
        }

        public String getPasswordPartSeperator() {
            return passwordPartSeperator;
        }

        public void setPasswordPartSeperator(String passwordPartSeperator) {
            this.passwordPartSeperator = passwordPartSeperator;
        }

        public String getAuthAdminDomainName() {
            return authAdminDomainName;
        }

        public void setAuthAdminDomainName(String authAdminDomainName) {
            this.authAdminDomainName = authAdminDomainName;
        }
    }
}