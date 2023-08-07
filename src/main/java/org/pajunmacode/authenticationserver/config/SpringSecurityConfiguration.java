package org.pajunmacode.authenticationserver.config;

import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;

@EnableWebSecurity
public class SpringSecurityConfiguration { //extends {// WebSecurityConfiguration {

//    @Bean
//    SecurityFilterChain configureSecurityFilterChain(HttpSecurity http) throws Exception {
//
//        http
//                .authorizeHttpRequests(authorizeRequests ->
//                        authorizeRequests
//                                .mvcMatchers("/connect/register")
//                                .permitAll()
//                                .anyRequest().authenticated())
//                .formLogin(Customizer.withDefaults());
//
//        return http.build();
//
//    }

//    @Bean
//    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
//        http.authorizeRequests()
//                .antMatchers(
//                        "/sample/**")
//                .permitAll()
//                .and()
//                .csrf().disable()
//                .formLogin();
//        http.csrf().disable();
//        return http.build();
//    }

//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//        http
//                .authorizeHttpRequests((authorize) -> authorize
//                        .mvcMatchers("/swagger-ui/**", "/api-docs/**").permitAll()
//                        .anyRequest().permitAll());
//
//                // register OAuth2 resource server
////                .oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt)
//
//                // register OAuth2 client
////                .oauth2Client(withDefaults());
//        http.csrf().disable();
//        return http.build();
//    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeRequests(authorizeRequests -> authorizeRequests.anyRequest()
                .authenticated())
                .formLogin(Customizer.withDefaults())
                .csrf().disable();
        return http.build();
    }


//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//        // @formatter:off
//        http
//                .authorizeRequests(a -> a
//                        .antMatchers("/connect/register", "/error", "/webjars/**").permitAll()
//                        .anyRequest().authenticated()
//                )
//                .exceptionHandling(e -> e
//                        .authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))
//                )
//                .oauth2Login();
//        // @formatter:on
//    }

}
