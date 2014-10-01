/*******************************************************************************
 *     Cloud Foundry 
 *     Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.scim.endpoints;

import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.rest.QueryableResourceManager;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.codehaus.jackson.annotate.JsonProperty;
import org.codehaus.jackson.map.ObjectMapper;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import java.io.IOException;
import java.sql.Timestamp;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.springframework.http.HttpStatus.CONFLICT;
import static org.springframework.http.HttpStatus.CREATED;

@Controller
public class CreateAccountEndpoints {

    public static final String SIGNUP_REDIRECT_URL = "signup_redirect_url";

    private final ObjectMapper objectMapper;
    private final QueryableResourceManager<ClientDetails> clientDetailsService;
    private final ScimUserProvisioning scimUserProvisioning;
    private final ExpiringCodeStore expiringCodeStore;
    private static final int CREATE_ACCOUNT_LIFETIME = 30 * 60 * 1000;

    public CreateAccountEndpoints(ObjectMapper objectMapper, QueryableResourceManager<ClientDetails> clientDetailsService, ScimUserProvisioning scimUserProvisioning, ExpiringCodeStore expiringCodeStore) {
        this.objectMapper = objectMapper;
        this.clientDetailsService = clientDetailsService;
        this.scimUserProvisioning = scimUserProvisioning;
        this.expiringCodeStore = expiringCodeStore;
    }

    @RequestMapping(value = "/create_account", method = RequestMethod.POST)
    public ResponseEntity<Map<String,String>> createAccount(@RequestBody AccountCreation accountCreation) throws IOException {
        List<ScimUser> results = scimUserProvisioning.query("userName eq \"" + accountCreation.getEmail() + "\" and origin eq \"" + Origin.UAA + "\"");
        ScimUser user;

        if (!results.isEmpty()) {
            if(results.get(0).isVerified()) {
                return new ResponseEntity<>(CONFLICT);
            } else {
                user = results.get(0);
            }
        } else {
            user = scimUserProvisioning.createUser(newScimUser(accountCreation.getEmail()), accountCreation.getPassword());
        }

        Map<String,String> codeData = new HashMap<>();
        codeData.put("user_id", user.getId());
        codeData.put("client_id", accountCreation.getClientId());
        ExpiringCode expiringCode = expiringCodeStore.generateCode(new ObjectMapper().writeValueAsString(codeData), new Timestamp(System.currentTimeMillis() + CREATE_ACCOUNT_LIFETIME));

        Map<String,String> response = new HashMap<>();
        response.put("user_id", user.getId());
        response.put("code", expiringCode.getCode());

        return new ResponseEntity<>(response, CREATED);
    }

    private ScimUser newScimUser(String emailAddress) {
        ScimUser scimUser = new ScimUser();
        scimUser.setUserName(emailAddress);
        scimUser.setPrimaryEmail(emailAddress);
        scimUser.setOrigin(Origin.UAA);
        scimUser.setVerified(false);
        scimUser.setActive(false);
        return scimUser;
    }

    private static class AccountCreation {
        @JsonProperty("email")
        private String email;

        @JsonProperty("password")
        private String password;

        @JsonProperty("client_id")
        private String clientId;

        public String getEmail() {
            return email;
        }

        public void setEmail(String email) {
            this.email = email;
        }

        public String getPassword() {
            return password;
        }

        public void setPassword(String password) {
            this.password = password;
        }

        public String getClientId() {
            return clientId;
        }

        public void setClientId(String clientId) {
            this.clientId = clientId;
        }
    }
}
