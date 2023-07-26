package org.pajunmacode.authenticationserver.service.impl;

import lombok.extern.slf4j.Slf4j;
import org.pajunmacode.authenticationserver.constant.Course;
import org.pajunmacode.authenticationserver.document.Student;
import org.pajunmacode.authenticationserver.repository.StudentRepository;
import org.pajunmacode.authenticationserver.service.StudentService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Slf4j
@Service
public class StudentServiceImpl implements StudentService {

    @Autowired
    StudentRepository studentRepository;

    @Override
    public String enrollStudentToComsci(Student student) {
        log.info("Enrolling student to Computer Science course");
        //student.setId(UUID.randomUUID().toString());
        student.setCourse(Course.COMPUTER_SCIENCE);
        return String.valueOf(studentRepository.insert(student));
    }

    @Override
    public List<Student> getStudentsByCourse(String course) {
        return studentRepository.findByCourse(course);
    }

    @Override
    public String expelStudentById(String id) {
        studentRepository.deleteById(id);
        return id.concat(" is expelled.");
    }

    @Override
    public String updateStudentRecord(Student student) {
        return String.valueOf(studentRepository.save(student));
    }
}
