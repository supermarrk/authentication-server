package org.pajunmacode.authenticationserver.config;

import lombok.extern.slf4j.Slf4j;
import org.bson.Document;
import org.bson.json.StrictJsonWriter;
import org.pajunmacode.authenticationserver.document.authuser.Authorization;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.Collections;
import java.util.List;

@Slf4j
@Component
public class UsernamePWAuthTokenConverter implements Converter<Document, UsernamePasswordAuthenticationToken> {

//    @Override
//    public UsernamePasswordAuthenticationToken convert(Authorization source) {
//        log.info("Instantiating UsernamePasswordAuthenticationToken >>>");
//        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
//                new UsernamePasswordAuthenticationToken(source.getPrincipalName(), source.getAuthorizationCodeValue());
//        return usernamePasswordAuthenticationToken;
//    }

    @Override
    public UsernamePasswordAuthenticationToken convert(Document source) {
        log.info("Instantiating UsernamePasswordAuthenticationToken >>>");
        Object principal = source.get("principal");
        Object credentials = source.get("authorities");

        List<GrantedAuthority> roles = Collections.singletonList(new SimpleGrantedAuthority("ADMIN"));

//                userRecord.get().getRoles().stream()
//                .map(SimpleGrantedAuthority::new)
//                .collect(Collectors.toList());

        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
                new UsernamePasswordAuthenticationToken(principal, credentials, roles);
        return usernamePasswordAuthenticationToken;
    }

    /**
    @Override
    @SuppressWarnings("unchecked")
    public OAuth2Authentication convert(DBObject source) {
        System.out.println(source);
        DBObject storedRequest = (DBObject)source.get("storedRequest");

        OAuth2Request oAuth2Request = new OAuth2Request((Map<String, String>)storedRequest.get("requestParameters"),
                (String)storedRequest.get("clientId"), null, true, new HashSet((List)storedRequest.get("scope")),
                null, null, null, null);
        DBObject userAuthorization = (DBObject)source.get("userAuthentication");
        Object principal = getPrincipalObject(userAuthorization.get("principal"));

        Authentication userAuthentication = new UsernamePasswordAuthenticationToken(principal,
                (String)userAuthorization.get("credentials"), getAuthorities((List) userAuthorization.get("authorities")));

        OAuth2Authentication authentication = new OAuth2Authentication(oAuth2Request,
                userAuthentication );
        return authentication;
    }

    private Object getPrincipalObject(Object principal) {
        if(principal instanceof DBObject) {
            DBObject principalDBObject = (DBObject)principal;
            Person user = new Person (principalDBObject);
            return user;
        } else {
            return principal;
        }
    }

    private Collection<GrantedAuthority> getAuthorities(List<Map<String, String>> authorities) {
        Set<GrantedAuthority> grantedAuthorities = new HashSet<GrantedAuthority>(authorities.size());
        for(Map<String, String> authority : authorities) {
            grantedAuthorities.add(new SimpleGrantedAuthority(authority.get("role")));
        }
        return grantedAuthorities;
    } */
}
