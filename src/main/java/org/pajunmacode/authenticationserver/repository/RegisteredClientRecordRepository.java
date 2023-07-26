package org.pajunmacode.authenticationserver.repository;

import org.pajunmacode.authenticationserver.document.authuser.RegisteredClientRecord;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RegisteredClientRecordRepository extends MongoRepository<RegisteredClientRecord, String> {
    Optional<RegisteredClientRecord> findByClientId(String id);
}
