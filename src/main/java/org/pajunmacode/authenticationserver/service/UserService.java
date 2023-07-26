package org.pajunmacode.authenticationserver.service;

import org.pajunmacode.authenticationserver.document.authuser.UserDetailsEntity;

public interface UserService {
    UserDetailsEntity createUserAccount(UserDetailsEntity user);
}
