package org.pajunmacode.authenticationserver.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfiguration {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/v1/student/enroll/computerscience")
                .permitAll()
                .and()
                .authorizeRequests()
                .antMatchers("/admin/**")
//                .hasRole("ADMIN")
//                .anyRequest()
                .authenticated()
                .and()
                .csrf().disable()
                .formLogin();
        return http.build();
    }
}
