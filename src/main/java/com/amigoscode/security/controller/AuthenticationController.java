package com.amigoscode.security.controller;

import com.amigoscode.security.entity.LoginResponseDTO;
import com.amigoscode.security.entity.RegistrationDTO;
import com.amigoscode.security.entity.User;
import com.amigoscode.security.service.AuthenticationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@CrossOrigin("*")
public class AuthenticationController {

    @Autowired
    private AuthenticationService authenticationService;

    @PostMapping("/register")
    public User registerUser(@RequestBody RegistrationDTO dto){

         return authenticationService.registerUser(dto.getUsername(), dto.getPassword());
    }

    @PostMapping("/login")
    public LoginResponseDTO loginUser(@RequestBody RegistrationDTO dto){
        return authenticationService.loginUser(dto.getUsername(), dto.getPassword());
    }



}
