package org.pajunmacode.authenticationserver.repository.oauth2;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.pajunmacode.authenticationserver.document.authuser.RegisteredClientRecord;
import org.pajunmacode.authenticationserver.repository.RegisteredClientRecordRepository;
import org.springframework.context.annotation.Primary;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

import java.util.*;

@Slf4j
@Component
@Primary
public class MongoRegisteredClientRepository implements RegisteredClientRepository {

    private final RegisteredClientRecordRepository registeredClientRecordRepository;
    private final ObjectMapper objectMapper = new ObjectMapper();
    public MongoRegisteredClientRepository(RegisteredClientRecordRepository registeredClientRecordRepository) {
        log.info("Initializing MongoRegisteredClientRepository...");
        Assert.notNull(registeredClientRecordRepository, "clientRepository cannot be null");
        this.registeredClientRecordRepository = registeredClientRecordRepository;

        ClassLoader classLoader = MongoRegisteredClientRepository.class.getClassLoader();
        List<Module> securityModules = SecurityJackson2Modules.getModules(classLoader);
        this.objectMapper.registerModules(securityModules);
        this.objectMapper.registerModule(new OAuth2AuthorizationServerJackson2Module());
    }

    @Override
    public void save(RegisteredClient registeredClient) {
        log.info("MongoRegisteredClientRepository save..");
        Assert.notNull(registeredClient, "registeredClient cannot be null");
        this.registeredClientRecordRepository.save(toEntity(registeredClient));
    }

    @Override
    public RegisteredClient findById(String id) {
        log.info("MongoRegisteredClientRepository findById: {}", id);
        Assert.hasText(id, "id cannot be empty");
        return this.registeredClientRecordRepository.findById(id).map(this::toObject).orElse(null);
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        log.info("MongoRegisteredClientRepository findByClientId: {}", clientId);
        Assert.hasText(clientId, "clientId cannot be empty");
        return this.registeredClientRecordRepository.findByClientId(clientId).map(this::toObject).orElse(null);
    }

    private RegisteredClient toObject(RegisteredClientRecord client) {
        log.info("MongoRegisteredClientRepository toObject: starts");
        // DEMO
//        Set<String> clientAuthenticationMethods = StringUtils.commaDelimitedListToSet(
//                client.getClientAuthenticationMethods());
//        Set<String> authorizationGrantTypes = StringUtils.commaDelimitedListToSet(
//                client.getAuthorizationGrantTypes());
//        Set<String> redirectUris = StringUtils.commaDelimitedListToSet(
//                client.getRedirectUris());
//        Set<String> clientScopes = StringUtils.commaDelimitedListToSet(
//                client.getScopes());

        Set<ClientAuthenticationMethod> clientAuthenticationMethods = client.getClientAuthenticationMethods();
        Set<AuthorizationGrantType> authorizationGrantTypes = client.getAuthorizationGrantTypes();
        Set<String> redirectUris = client.getRedirectUris();
        Set<String> clientScopes = client.getScopes();

        RegisteredClient.Builder builder = RegisteredClient
                .withId(client.getId())
                .clientId(client.getClientId())
//                .clientIdIssuedAt(client.getClientIdIssuedAt())
                .clientSecret(client.getClientSecret())
//                .clientSecretExpiresAt(client.getClientSecretExpiresAt())
//                .clientName(client.getClientName())
                .clientAuthenticationMethods(authenticationMethods ->
                        authenticationMethods.addAll(clientAuthenticationMethods))
//                .authorizationGrantTypes((grantTypes) ->
//                        grantTypes.addAll(authorizationGrantTypes))
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUris((uris) -> uris.addAll(redirectUris))
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.EMAIL)
                .scope(OidcScopes.PROFILE)
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(false)
                        .requireProofKey(true)
                        .build());

//        Map<String, Object> clientSettingsMap = parseMap(client.getClientSettings());
//        builder.clientSettings(ClientSettings.withSettings(clientSettingsMap).build());

//        builder.clientSettings(client.getClientSettings());

//        Map<String, Object> tokenSettingsMap = parseMap(client.getTokenSettings());
//        builder.tokenSettings(TokenSettings.withSettings(tokenSettingsMap).build());

//        builder.tokenSettings(client.getTokenSettings());
        log.info("MongoRegisteredClientRepository toObject: done");

        return builder.build();

//        return RegisteredClient
//                .withId(client.getId())
//                .clientId("apple-m3")
////                .clientSecret("{noop}pajunma-secret")
//                .clientSecret("password")
////                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
//                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
//                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
//                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
////                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
//                .scope(OidcScopes.OPENID)
//                .scope(OidcScopes.EMAIL)
//                .scope(OidcScopes.PROFILE)
//                .clientSettings(ClientSettings.builder()
//                        .requireAuthorizationConsent(false)
//                        .requireProofKey(true)
//                        .build())
////                .redirectUri("http://127.0.0.1:8082/login/oauth2/code/pkce") // Localhost not allowed
//                .redirectUri("https://google.com") // Localhost not allowed
//                .build();
    }

    private RegisteredClientRecord toEntity(RegisteredClient registeredClient) {
        log.info("MongoRegisteredClientRepository toEntity starts");
        List<String> clientAuthenticationMethods = new ArrayList<>(registeredClient.getClientAuthenticationMethods().size());
        registeredClient.getClientAuthenticationMethods().forEach(clientAuthenticationMethod ->
                clientAuthenticationMethods.add(clientAuthenticationMethod.getValue()));

        List<String> authorizationGrantTypes = new ArrayList<>(registeredClient.getAuthorizationGrantTypes().size());
        registeredClient.getAuthorizationGrantTypes().forEach(authorizationGrantType ->
                authorizationGrantTypes.add(authorizationGrantType.getValue()));

        RegisteredClientRecord entity = new RegisteredClientRecord();
        entity.setId(registeredClient.getId());
        entity.setClientId(registeredClient.getClientId());
        entity.setClientIdIssuedAt(registeredClient.getClientIdIssuedAt());
        entity.setClientSecret(registeredClient.getClientSecret());
        entity.setClientSecretExpiresAt(registeredClient.getClientSecretExpiresAt());
        entity.setClientName(registeredClient.getClientName());
//        entity.setClientAuthenticationMethods(StringUtils.collectionToCommaDelimitedString(clientAuthenticationMethods));
//        entity.setAuthorizationGrantTypes(StringUtils.collectionToCommaDelimitedString(authorizationGrantTypes));
//        entity.setRedirectUris(StringUtils.collectionToCommaDelimitedString(registeredClient.getRedirectUris()));
//        entity.setScopes(StringUtils.collectionToCommaDelimitedString(registeredClient.getScopes()));
//        entity.setClientSettings(writeMap(registeredClient.getClientSettings().getSettings()));
//        entity.setTokenSettings(writeMap(registeredClient.getTokenSettings().getSettings()));

        entity.setClientAuthenticationMethods(registeredClient.getClientAuthenticationMethods());
        entity.setAuthorizationGrantTypes(registeredClient.getAuthorizationGrantTypes());
        entity.setRedirectUris(registeredClient.getRedirectUris());
        entity.setScopes(registeredClient.getScopes());
        entity.setClientSettings(registeredClient.getClientSettings());
        entity.setTokenSettings(registeredClient.getTokenSettings());

        return entity;
    }

    private Map<String, Object> parseMap(String data) {
        try {
            return this.objectMapper.readValue(data, new TypeReference<Map<String, Object>>() {
            });
        } catch (Exception ex) {
            throw new IllegalArgumentException(ex.getMessage(), ex);
        }
    }

    private String writeMap(Map<String, Object> data) {
        try {
            return this.objectMapper.writeValueAsString(data);
        } catch (Exception ex) {
            throw new IllegalArgumentException(ex.getMessage(), ex);
        }
    }

    private static AuthorizationGrantType resolveAuthorizationGrantType(String authorizationGrantType) {
        if (AuthorizationGrantType.AUTHORIZATION_CODE.getValue().equals(authorizationGrantType)) {
            return AuthorizationGrantType.AUTHORIZATION_CODE;
        } else if (AuthorizationGrantType.CLIENT_CREDENTIALS.getValue().equals(authorizationGrantType)) {
            return AuthorizationGrantType.CLIENT_CREDENTIALS;
        } else if (AuthorizationGrantType.REFRESH_TOKEN.getValue().equals(authorizationGrantType)) {
            return AuthorizationGrantType.REFRESH_TOKEN;
        }
        return new AuthorizationGrantType(authorizationGrantType);              // Custom authorization grant type
    }

    private static ClientAuthenticationMethod resolveClientAuthenticationMethod(String clientAuthenticationMethod) {
        if (ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue().equals(clientAuthenticationMethod)) {
            return ClientAuthenticationMethod.CLIENT_SECRET_BASIC;
        } else if (ClientAuthenticationMethod.CLIENT_SECRET_POST.getValue().equals(clientAuthenticationMethod)) {
            return ClientAuthenticationMethod.CLIENT_SECRET_POST;
        } else if (ClientAuthenticationMethod.NONE.getValue().equals(clientAuthenticationMethod)) {
            return ClientAuthenticationMethod.NONE;
        }
        return new ClientAuthenticationMethod(clientAuthenticationMethod);      // Custom client authentication method
    }
}
