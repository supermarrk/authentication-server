package org.pajunmacode.authenticationserver.api;

import org.pajunmacode.authenticationserver.document.Student;
import org.pajunmacode.authenticationserver.service.StudentService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/v1/student")
public class StudentApi {

    @Autowired
    private StudentService studentService;

    @PostMapping("/enroll/computerscience")
    public ResponseEntity<String> enrollStudent(@RequestBody Student student) {
        return new ResponseEntity<>(studentService.enrollStudentToComsci(student), HttpStatus.OK);
    }

    @GetMapping("/find")
    public ResponseEntity<List<Student>> findStudentByEmail(@RequestParam("course") String course) {
        return new ResponseEntity<>(studentService.getStudentsByCourse(course), HttpStatus.OK);
    }

    @DeleteMapping("/expel")
    public ResponseEntity<String> expelStudent(@RequestParam("id") String id) {
        return new ResponseEntity<>(studentService.expelStudentById(id), HttpStatus.OK);
    }

    @PutMapping("/update")
    public ResponseEntity<String> updateStudentRecord(@RequestBody Student student) {
        return new ResponseEntity<>(studentService.updateStudentRecord(student), HttpStatus.OK);
    }
}
