package org.pajunmacode.authenticationserver.document;

import lombok.Data;
import org.pajunmacode.authenticationserver.constant.Course;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

@Data
@Document
public class Student {
    @Id
    private String id;
    private String firstName;
    private String middleName;
    private String lastName;
    private short age;
    private Course course;
    private Contact contact;
}
