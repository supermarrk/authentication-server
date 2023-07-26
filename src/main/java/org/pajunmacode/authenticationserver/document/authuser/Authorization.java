package org.pajunmacode.authenticationserver.document.authuser;

import java.time.Instant;
import java.util.Map;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

@Data
@Document
@AllArgsConstructor
@NoArgsConstructor
public class Authorization {

//    @Id
//    private String id;
//    private String registeredClientId;
//    private String principalName;
//    private String authorizationGrantType;
//    private String authorizedScopes;
//    private Map attributes;
//    private String state;
//
//    private String authorizationCodeValue;
//    private Instant authorizationCodeIssuedAt;
//    private Instant authorizationCodeExpiresAt;
//    private Map authorizationCodeMetadata;
//
//    private String accessTokenValue;
//    private Instant accessTokenIssuedAt;
//    private Instant accessTokenExpiresAt;
//    private Map accessTokenMetadata;
//    private String accessTokenType;
//    private String accessTokenScopes;
//
//    private String refreshTokenValue;
//    private Instant refreshTokenIssuedAt;
//    private Instant refreshTokenExpiresAt;
//    private Map refreshTokenMetadata;
//
//    private String oidcIdTokenValue;
//    private Instant oidcIdTokenIssuedAt;
//    private Instant oidcIdTokenExpiresAt;
//    private Map oidcIdTokenMetadata;
//    private String oidcIdTokenClaims;
//
//    private String userCodeValue;
//    private Instant userCodeIssuedAt;
//    private Instant userCodeExpiresAt;
//    private String userCodeMetadata;
//
//    private String deviceCodeValue;
//    private Instant deviceCodeIssuedAt;
//    private Instant deviceCodeExpiresAt;
//    private String deviceCodeMetadata;

    @Id
    private String id;
    private String registeredClientId;
    private String principalName;
    private String authorizationGrantType;
    private String attributes;
    private String state;

    private String authorizationCodeValue;
    private Instant authorizationCodeIssuedAt;
    private Instant authorizationCodeExpiresAt;
    private String authorizationCodeMetadata;

    private String accessTokenValue;
    private Instant accessTokenIssuedAt;
    private Instant accessTokenExpiresAt;
    private String accessTokenMetadata;
    private String accessTokenType;
    private String accessTokenScopes;

    private String refreshTokenValue;
    private Instant refreshTokenIssuedAt;
    private Instant refreshTokenExpiresAt;
    private String refreshTokenMetadata;

    private String oidcIdTokenValue;
    private Instant oidcIdTokenIssuedAt;
    private Instant oidcIdTokenExpiresAt;
    private String oidcIdTokenMetadata;
    private String oidcIdTokenClaims;

}


