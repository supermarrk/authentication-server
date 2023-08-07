package org.pajunmacode.authenticationserver.config;

import com.google.gson.Gson;
import lombok.extern.slf4j.Slf4j;
import org.pajunmacode.authenticationserver.repository.RegisteredClientRecordRepository;
import org.pajunmacode.authenticationserver.repository.oauth2.MongoRegisteredClientRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.UUID;

@Slf4j
@Configuration
public class AuthServerConfiguration {

    @Autowired
    @Qualifier("registeredClientRecordRepository")
    private RegisteredClientRecordRepository registeredClientRecordRepository;

    @Autowired
    JwtToUserConverter jwtToUserConverter;

    /**
     * Spring Security filter chain for the Protocol Endpoints.
     */
    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {

        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .oidc(customCustomizer());	// Enable OpenID Connect 1.0

        http
                .oauth2ResourceServer((oauth2) -> oauth2.jwt(Customizer.withDefaults()))
                .exceptionHandling((exceptions) -> exceptions
                        .defaultAuthenticationEntryPointFor(
                                new LoginUrlAuthenticationEntryPoint("/login"),
                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                        )
                );

        // Enable OpenID Connect Client Registration
//        http.apply(authorizationServerConfigurer);
//
//        authorizationServerConfigurer
//                .oidc(oidc -> {
//                    oidc.clientRegistrationEndpoint(Customizer.withDefaults());
//                    oidc.userInfoEndpoint(Customizer.withDefaults());
//                    }
//
//                );
//        http.apply(authorizationServerConfigurer);


        return http.build();

//        return http.formLogin(Customizer.withDefaults()).build();
    }

    public AuthorizationServerCustomConfigs customCustomizer() {
        return new AuthorizationServerCustomConfigs();
    }

    // OpenID Connect 1.0 Client Registration Endpoint
//    @Bean
//    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
//        OAuth2AuthorizationServerConfigurer<HttpSecurity> authorizationServerConfigurer =
//                new OAuth2AuthorizationServerConfigurer<>();
//        http.apply(authorizationServerConfigurer);
//
//        authorizationServerConfigurer
//                .oidc(oidc ->
//                        oidc.clientRegistrationEndpoint(Customizer.withDefaults())
//                );
//
//        return http.build();
//    }



//    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
//
//        OAuth2AuthorizationServerConfigurer<HttpSecurity> authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer<>();
//
//        http
//                .requestMatcher(authorizationServerConfigurer
//                        .getEndpointsMatcher()).authorizeRequests(authorize ->
//                        authorize
//                                .mvcMatchers("/admin/create-account", "/connect/register", "/oauth2/token")
//                                .permitAll()
//                                .anyRequest()
//                                .authenticated());
//        http
//                .exceptionHandling(exceptions ->
//                        exceptions.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")))
//                .csrf( csrf ->
//                        csrf
//                                .ignoringRequestMatchers(authorizationServerConfigurer.getEndpointsMatcher()))
//                .apply(authorizationServerConfigurer);
//
//        // Required by /userinfo endpoint
////        http.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);
//        http
//                .oauth2ResourceServer((oauth2) -> oauth2.jwt((jwt) ->
//                        jwt.jwtAuthenticationConverter(jwtToUserConverter))
//                );
//        return http.build();
//    }

//    @Bean
//    @Order(2)
//    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
//        return http
//                .formLogin(Customizer.withDefaults())
//                .build();
//    }

    @Bean
//    @Primary
    @Order(3)
    public RegisteredClientRepository registeredClientRepository() {
        return new MongoRegisteredClientRepository(registeredClientRecordRepository);
    }

    /**
    @Bean
    public RegisteredClientRepository registeredClientRepository() {

        RegisteredClient pkceClient = RegisteredClient
                .withId(UUID.randomUUID().toString())
                .clientId("apple2")
                .clientSecret("apple2")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.EMAIL)
                .scope(OidcScopes.PROFILE)
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(false)
                        .requireProofKey(true)
                        .build())
//                .redirectUri("http://127.0.0.1:8082/login/oauth2/code/pkce") // Localhost not allowed
                .redirectUri("https://google.com") // Localhost not allowed
                .build();

//        RegisteredClientDTO registeredClientDTO = Mappers.getMapper(RegisteredClientMapper.class).mapFrom(pkceClient);
        RegisteredClientRecord registeredClientRecord = Mappers.getMapper(RegisteredClientMapper.class).mapFrom(pkceClient);

        // Manual mapping
        RegisteredClientRecord clientRecord = RegisteredClientRecord.builder()
                .id(pkceClient.getId())
                .clientId("apple2")
                .clientSecret("apple2")
//                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
//                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
//                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
//                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
//                .scope(OidcScopes.OPENID)
//                .scope(OidcScopes.EMAIL)
//                .scope(OidcScopes.PROFILE)
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(false)
                        .requireProofKey(true)
                        .build())
//                .redirectUri("http://127.0.0.1:8082/login/oauth2/code/pkce") // Localhost not allowed
//                .redirectUri("https://google.com") // Localhost not allowed
                .build();

        clientRecord.setClientAuthenticationMethods(pkceClient.getClientAuthenticationMethods());
        clientRecord.setAuthorizationGrantTypes(pkceClient.getAuthorizationGrantTypes());
        clientRecord.setScopes(pkceClient.getScopes());
        clientRecord.setRedirectUris(pkceClient.getRedirectUris());
//        clientRecord.setTokenSettings(new Gson().toJson(pkceClient.getTokenSettings()));

        log.info("HERE {}", new Gson().toJson(registeredClientRecord));
//        registeredClientRecordRepository.insert(registeredClientRecord);
        registeredClientRecordRepository.insert(clientRecord);
        log.info(new Gson().toJson(pkceClient));
        List<RegisteredClientRecord> registeredClientRecords = registeredClientRecordRepository.findAll();
        List<RegisteredClientDTO> registeredClients = Mappers.getMapper(RegisteredClientMapper.class).mapFrom(registeredClientRecords);
        log.info("DITO {}", new Gson().toJson(registeredClientRecord));
        return new InMemoryRegisteredClientRepository(pkceClient);
//        return new
    }  */

//    @Bean
//    public RegisteredClientRepository registeredClientRepository() {
//
//        RegisteredClient pkceClient = RegisteredClient
//                .withId(UUID.randomUUID().toString())
//                .clientId("pajunma-client")
//                .clientSecret("{noop}pajunma-secret")
//                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
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
//
//        log.info(new Gson().toJson(pkceClient));
//        return new InMemoryRegisteredClientRepository(pkceClient);
//    }

//    @Bean
//    public ProviderSettings providerSettings() {
//        return ProviderSettings
//                .builder()
//                .build();
//    }

    /**
     * This is the iss
     */
    @Bean
    public ProviderSettings providerSettings() {
        return ProviderSettings.builder()
                .issuer("http://auth-server:8080")
//                .oidcClientRegistrationEndpoint("http://auth-server:8080/connect/register")
                .oidcClientRegistrationEndpoint("/clientinfo")
                .build();
    }

}

