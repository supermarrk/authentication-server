package org.pajunmacode.authenticationserver.service.impl;

import lombok.extern.slf4j.Slf4j;
import org.pajunmacode.authenticationserver.model.authuser.UserDetailsEntity;
import org.pajunmacode.authenticationserver.repository.UserDetailsEntityRepository;
import org.pajunmacode.authenticationserver.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Slf4j
@Service
public class UserServiceImpl implements UserService {

    @Autowired
    private UserDetailsEntityRepository userDetailsEntityRepository;

    @Override
    public UserDetailsEntity createUserAccount(UserDetailsEntity user) {
        log.info("Saving new user...");
        return userDetailsEntityRepository.insert(user);
    }
}
