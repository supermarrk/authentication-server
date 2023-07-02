package org.pajunmacode.authenticationserver.repository;

import org.pajunmacode.authenticationserver.model.Student;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface StudentRepository extends MongoRepository<Student, String> {

    List<Student> findByCourse(String course);
}
