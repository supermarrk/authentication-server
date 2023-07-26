package org.pajunmacode.authenticationserver.config;

import lombok.extern.slf4j.Slf4j;
import org.pajunmacode.authenticationserver.document.authuser.UserDetailsEntity;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

import java.util.Collections;

@Slf4j
@Component
public class JwtToUserConverter implements Converter<Jwt, UsernamePasswordAuthenticationToken> {
    @Override
    public UsernamePasswordAuthenticationToken convert(Jwt source) {
        log.info("UsernamePasswordAuthenticationToken convert(Jwt source)");
        UserDetailsEntity user = new UserDetailsEntity();
        user.setId(source.getSubject());
        return new UsernamePasswordAuthenticationToken(user, source, Collections.emptyList());
    }
}
