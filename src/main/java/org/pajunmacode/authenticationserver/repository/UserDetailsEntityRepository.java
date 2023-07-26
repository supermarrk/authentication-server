package org.pajunmacode.authenticationserver.repository;

import org.pajunmacode.authenticationserver.document.authuser.UserDetailsEntity;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserDetailsEntityRepository  extends MongoRepository<UserDetailsEntity, String> {
    Optional<UserDetailsEntity> findByUsername(String username);
    boolean existsByUsername(String username);
}
