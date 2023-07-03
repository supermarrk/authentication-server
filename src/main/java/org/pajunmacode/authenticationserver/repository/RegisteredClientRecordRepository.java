package org.pajunmacode.authenticationserver.repository;

import org.pajunmacode.authenticationserver.model.authuser.RegisteredClientRecord;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface RegisteredClientRecordRepository extends MongoRepository<RegisteredClientRecord, String> {
}
