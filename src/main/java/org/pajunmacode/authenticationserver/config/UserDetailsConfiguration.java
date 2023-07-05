package org.pajunmacode.authenticationserver.config;

import org.pajunmacode.authenticationserver.model.authuser.UserDetailsEntity;
import org.pajunmacode.authenticationserver.repository.UserDetailsEntityRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Configuration
public class UserDetailsConfiguration implements UserDetailsService {

    @Autowired
    private UserDetailsEntityRepository userDetailsEntityRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        final Optional<UserDetailsEntity> userRecord = userDetailsEntityRepository.findByUsername(username);
        if (!userRecord.isPresent()) {
            throw new UsernameNotFoundException(username);
        }

        List<GrantedAuthority> roles = userRecord.get().getRoles().stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());

        UserDetails user = User
                .withUsername(userRecord.get().getUsername())
                .password(userRecord.get().getPassword())
                .authorities(roles).build();
        return user;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

//    @Bean
//    public UserDetailsService userDetailsService() {
//        UserDetails userDetails = User.withDefaultPasswordEncoder()
//                .username("user")
//                .password("password")
//                .roles("USER", "ADMIN")
//                .build();
//
//        return new InMemoryUserDetailsManager(userDetails);
//    }

}
