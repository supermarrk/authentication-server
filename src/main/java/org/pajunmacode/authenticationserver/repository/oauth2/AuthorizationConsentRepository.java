package org.pajunmacode.authenticationserver.repository.oauth2;

import org.pajunmacode.authenticationserver.document.authuser.AuthorizationConsent;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface AuthorizationConsentRepository extends MongoRepository<AuthorizationConsent, String>  {
    Optional<AuthorizationConsent> findByRegisteredClientIdAndPrincipalName(String registeredClientId, String principalName);
    void deleteByRegisteredClientIdAndPrincipalName(String registeredClientId, String principalName);
}
