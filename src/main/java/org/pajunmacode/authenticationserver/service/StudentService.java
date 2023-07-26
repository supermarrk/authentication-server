package org.pajunmacode.authenticationserver.service;

import org.pajunmacode.authenticationserver.document.Student;

import java.util.List;

public interface StudentService {
    String enrollStudentToComsci(Student student);
    List<Student> getStudentsByCourse(String course);
    String expelStudentById(String id);

    String updateStudentRecord(Student student);
}
