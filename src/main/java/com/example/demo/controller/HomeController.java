package com.example.demo.controller;

import com.example.demo.security.IcesiSecurityContext;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.text.ParseException;

@RestController
public class HomeController {

    @GetMapping("/home")
    public String home() throws ParseException {
        return "Hello, " + IcesiSecurityContext.getCurrentUserId();
    }

    @GetMapping("/admin")
    public String admin() throws ParseException {
        return "Hello, admin " + IcesiSecurityContext.getCurrentUserId() + " " + IcesiSecurityContext.getCurrentUserRole();
    }


}
