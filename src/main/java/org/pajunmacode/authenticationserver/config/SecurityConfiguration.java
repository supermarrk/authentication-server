//package org.pajunmacode.authenticationserver.config;
//
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//import org.springframework.security.config.web.server.ServerHttpSecurity;
//import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
//import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestCustomizers;
//import org.springframework.security.oauth2.client.web.server.DefaultServerOAuth2AuthorizationRequestResolver;
//import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizationRequestResolver;
//import org.springframework.security.oauth2.core.AuthorizationGrantType;
//import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
//import org.springframework.security.oauth2.core.oidc.OidcScopes;
//import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
//import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
//import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
//import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
//import org.springframework.security.web.SecurityFilterChain;
//import org.springframework.security.web.server.SecurityWebFilterChain;
//
//import java.util.UUID;
//
//@Configuration
//public class SecurityConfiguration {
//
//    @Bean
//    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
//        http.authorizeRequests()
//                .antMatchers("/v1/student/enroll/computerscience", "/v1/student/find?course=POLITICAL_SCIENCE")
//                .permitAll()
//                .and()
////                .authorizeRequests()
////                .anyRequest()
//////                .antMatchers("/admin/**")
//////                .hasRole("ADMIN")
//////                .anyRequest()
////                .authenticated()
////                .and()
//                .csrf().disable()
//                .formLogin();
//        return http.build();
//    }
//
////    @Bean
////    public SecurityWebFilterChain pkceFilterChain(ServerHttpSecurity http,
////                                                  ServerOAuth2AuthorizationRequestResolver resolver) {
////        http.authorizeExchange(r -> r.anyExchange().authenticated());
////        http.oauth2Login(auth -> auth.authorizationRequestResolver(resolver));
////        return http.build();
////    }
////
////    @Bean
////    public ServerOAuth2AuthorizationRequestResolver pkceResolver(ReactiveClientRegistrationRepository repo) {
////        var resolver = new DefaultServerOAuth2AuthorizationRequestResolver(repo);
////        resolver.setAuthorizationRequestCustomizer(OAuth2AuthorizationRequestCustomizers.withPkce());
////        return resolver;
////    }
////
////    @Bean
////    public RegisteredClientRepository registeredClientRepository() {
////        var pkceClient = RegisteredClient
////                .withId(UUID.randomUUID().toString())
////                .clientId("pkce-client")
////                .clientSecret("{noop}obscura")
////                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
////                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
////                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
////                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
////                .scope(OidcScopes.OPENID)
////                .scope(OidcScopes.EMAIL)
////                .scope(OidcScopes.PROFILE)
////                .clientSettings(ClientSettings.builder()
////                        .requireAuthorizationConsent(false)
////                        .requireProofKey(true)
////                        .build())
////                .redirectUri("http://127.0.0.1:8080/login/oauth2/code/pkce")
////                .build();
////
////        return new InMemoryRegisteredClientRepository(pkceClient);
////    }
//
//}
