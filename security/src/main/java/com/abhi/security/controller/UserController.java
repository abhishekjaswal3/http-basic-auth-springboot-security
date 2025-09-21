package com.abhi.security.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/user")
public class UserController {


    @GetMapping("/hello")
    public ResponseEntity<?> sayHello(){
        return new ResponseEntity<>("Hello new user",HttpStatus.OK);
    }

    @GetMapping("/above-all")
    public ResponseEntity<?> oneAboveAll(){
        return new ResponseEntity<>("you are admin, so u are able to see this response",HttpStatus.OK);
    }
}
