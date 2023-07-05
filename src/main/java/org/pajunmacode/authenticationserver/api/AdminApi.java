package org.pajunmacode.authenticationserver.api;

import org.pajunmacode.authenticationserver.model.authuser.UserDetailsEntity;
import org.pajunmacode.authenticationserver.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

@RestController
@RequestMapping("/admin")
public class AdminApi {

    @Autowired
    private UserService userService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @PostMapping("/create-account")
    public ResponseEntity<UserDetailsEntity> createAccount(@RequestBody UserDetailsEntity user) {
        user.setId(UUID.randomUUID().toString());
        String encodedPw = passwordEncoder.encode(user.getPassword());
        user.setPassword(encodedPw);
        return new ResponseEntity<>(userService.createUserAccount(user), HttpStatus.OK);
    }
}
