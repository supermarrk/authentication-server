package org.pajunmacode.authenticationserver.document.authuser;

import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

@Data
@Document
//@IdClass(AuthorizationConsent.AuthorizationConsentId.class)
public class AuthorizationConsent {
    @Id
    private String registeredClientId;
    @Indexed(unique = true)
    private String principalName;

//    @Id
//    private AuthorizationConsentId id;
    private String authorities;

//    @Data
//    public static class AuthorizationConsentId implements Serializable {
//        private String registeredClientId;
//        private String principalName;
//
//        @Override
//        public boolean equals(Object o) {
//            if (this == o) return true;
//            if (o == null || getClass() != o.getClass()) return false;
//            AuthorizationConsentId that = (AuthorizationConsentId) o;
//            return registeredClientId.equals(that.registeredClientId) && principalName.equals(that.principalName);
//        }
//
//        @Override
//        public int hashCode() {
//            return Objects.hash(registeredClientId, principalName);
//        }
//    }
}
