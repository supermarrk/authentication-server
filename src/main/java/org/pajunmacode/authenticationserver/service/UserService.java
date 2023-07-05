package org.pajunmacode.authenticationserver.service;

import org.pajunmacode.authenticationserver.model.authuser.UserDetailsEntity;

public interface UserService {
    UserDetailsEntity createUserAccount(UserDetailsEntity user);
}
