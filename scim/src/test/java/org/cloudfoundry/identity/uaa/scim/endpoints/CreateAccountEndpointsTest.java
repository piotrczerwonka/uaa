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
import org.codehaus.jackson.map.ObjectMapper;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.sql.Timestamp;
import java.util.Arrays;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class CreateAccountEndpointsTest {

    private MockMvc mockMvc;
    private ScimUserProvisioning scimUserProvisioning;
    private ExpiringCodeStore expiringCodeStore;
    private QueryableResourceManager<ClientDetails> clientDetailsService;

    @Before
    public void setUp() throws Exception {
        scimUserProvisioning = mock(ScimUserProvisioning.class);
        expiringCodeStore = mock(ExpiringCodeStore.class);
        clientDetailsService = mock(QueryableResourceManager.class);
        CreateAccountEndpoints controller = new CreateAccountEndpoints(new ObjectMapper(), clientDetailsService, scimUserProvisioning, expiringCodeStore);
        mockMvc = MockMvcBuilders.standaloneSetup(controller).build();
    }

    @Test
    public void testCreatingAnAccountSuccessfully() throws Exception {
        when(expiringCodeStore.generateCode(eq("{\"user_id\":\"newly-created-user-id\",\"client_id\":\"login\"}"), any(Timestamp.class)))
                .thenReturn(new ExpiringCode("secret_code", new Timestamp(System.currentTimeMillis()), "{\"username\":\"user@example.com\",\"client_id\":\"app\"}"));

        when(scimUserProvisioning.createUser(any(ScimUser.class), eq("secret")))
            .thenAnswer(new Answer<ScimUser>() {
                @Override
                public ScimUser answer(InvocationOnMock invocationOnMock) throws Throwable {
                    ScimUser u = (ScimUser) invocationOnMock.getArguments()[0];
                    u.setId("newly-created-user-id");
                    return u;
                }
            });

        MockHttpServletRequestBuilder post = post("/create_account")
                .contentType(APPLICATION_JSON)
                .content("{\"email\":\"user@example.com\",\"password\":\"secret\",\"client_id\":\"login\"}")
                .accept(APPLICATION_JSON);

        mockMvc.perform(post)
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.user_id").value("newly-created-user-id"))
                .andExpect(jsonPath("$.code").value("secret_code"));

        ArgumentCaptor<ScimUser> scimUserCaptor = ArgumentCaptor.forClass(ScimUser.class);
        Mockito.verify(scimUserProvisioning).createUser(scimUserCaptor.capture(), eq("secret"));
        Assert.assertEquals("user@example.com", scimUserCaptor.getValue().getUserName());
        Assert.assertEquals("user@example.com", scimUserCaptor.getValue().getPrimaryEmail());
        Assert.assertEquals("newly-created-user-id", scimUserCaptor.getValue().getId());
        Assert.assertEquals(Origin.UAA, scimUserCaptor.getValue().getOrigin());
        Assert.assertEquals(false, scimUserCaptor.getValue().isActive());
        Assert.assertEquals(false, scimUserCaptor.getValue().isVerified());
    }

    @Test
    public void testCreatingAnAccountWhenUserExists() throws Exception {
        ScimUser existingUser = new ScimUser();
        existingUser.setVerified(true);

        when(scimUserProvisioning.query("userName eq \"user@example.com\" and origin eq \"uaa\""))
            .thenReturn(Arrays.asList(existingUser));

        MockHttpServletRequestBuilder post = post("/create_account")
            .contentType(APPLICATION_JSON)
            .content("{\"email\":\"user@example.com\",\"password\":\"secret\",\"client_id\":\"login\"}")
            .accept(APPLICATION_JSON);

        mockMvc.perform(post)
            .andExpect(status().isConflict());
    }

    @Test
    public void testCreatingAnAccountWhenUnverifiedUserExists() throws Exception {
        ScimUser existingUser = new ScimUser();
        existingUser.setVerified(false);
        existingUser.setId("unverified-user-id");

        when(expiringCodeStore.generateCode(eq("{\"user_id\":\"unverified-user-id\",\"client_id\":\"login\"}"), any(Timestamp.class)))
            .thenReturn(new ExpiringCode("secret_code", new Timestamp(System.currentTimeMillis()), "{\"username\":\"user@example.com\",\"client_id\":\"app\"}"));

        when(scimUserProvisioning.query("userName eq \"user@example.com\" and origin eq \"uaa\""))
            .thenReturn(Arrays.asList(existingUser));

        MockHttpServletRequestBuilder post = post("/create_account")
            .contentType(APPLICATION_JSON)
            .content("{\"email\":\"user@example.com\",\"password\":\"secret\",\"client_id\":\"login\"}")
            .accept(APPLICATION_JSON);

        mockMvc.perform(post)
            .andExpect(status().isCreated())
            .andExpect(jsonPath("$.user_id").value("unverified-user-id"))
            .andExpect(jsonPath("$.code").value("secret_code"));
    }
}
