package org.pajunmacode.authenticationserver.repository.oauth2;

import java.util.Optional;

import org.pajunmacode.authenticationserver.document.authuser.Authorization;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface AuthorizationRepository extends MongoRepository<Authorization, String> {
    Optional<Authorization> findByState(String state);
//    Optional<Authorization> findByAuthorizationCodeValue(String authorizationCode);
    Authorization findByAuthorizationCodeValue(String authorizationCode);
//    Object findByAuthorizationCodeValue(String authorizationCode);
    Optional<Authorization> findByAccessTokenValue(String accessToken);
    Optional<Authorization> findByRefreshTokenValue(String refreshToken);
//    @Query("select a from Authorization a where a.state = :token" +
//            " or a.authorizationCodeValue = :token" +
//            " or a.accessTokenValue = :token" +
//            " or a.refreshTokenValue = :token"
//    )
//    Optional<Authorization> findByStateOrAuthorizationCodeValueOrAccessTokenValueOrRefreshTokenValue(@Param("token") String token);
}


