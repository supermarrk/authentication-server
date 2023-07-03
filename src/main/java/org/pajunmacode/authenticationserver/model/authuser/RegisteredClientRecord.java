package org.pajunmacode.authenticationserver.model.authuser;

import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.util.List;

@Data
@Document
public class RegisteredClientRecord {

    @Id
    private String id;
    private String clientId;
    private String clienId;
    private String clientName;
    private List<ClientAuthenticationMethod> clientAuthenticationMethods;
    private List<AuthorizationGrantType> authorizationGrantTypes;
    private List<String> redirectUris;
    private List<String> scopes;
//    private String clientSettings;
//    private String tokenSettings;

    @Data
    public class AuthorizationGrantType {
        private String value;
    }

    @Data
    public class ClientAuthenticationMethod {
        private String value;
    }



    /**
     * RegisteredClient pkceClient = RegisteredClient
     *             .withId(UUID.randomUUID().toString())
     *             .clientId("pkce-client")
     *             .clientSecret("{noop}obscura")
     *             .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
     *             .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
     *             .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
     *             .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
     *             .scope(OidcScopes.OPENID)
     *             .scope(OidcScopes.EMAIL)
     *             .scope(OidcScopes.PROFILE)
     *             .clientSettings(ClientSettings.builder()
     *               .requireAuthorizationConsent(false)
     *               .requireProofKey(true)
     *               .build())
     *             .redirectUri("http://127.0.0.1:8080/login/oauth2/code/pkce") // Localhost not allowed
     *             .build();
     */
}
