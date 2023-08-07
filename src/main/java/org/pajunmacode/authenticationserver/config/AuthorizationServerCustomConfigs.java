package org.pajunmacode.authenticationserver.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OidcConfigurer;
import org.springframework.stereotype.Component;

@Component
public class AuthorizationServerCustomConfigs implements Customizer<OidcConfigurer> {

    @Override
    public void customize(OidcConfigurer oidcConfigurer) {
        oidcConfigurer.clientRegistrationEndpoint(Customizer.withDefaults());
        oidcConfigurer.userInfoEndpoint(Customizer.withDefaults());
    }
}
