package com.example.demo.controller;

import com.example.demo.dto.LoginDTO;
import com.example.demo.dto.TokenDTO;
import com.example.demo.service.TokenService;
import lombok.AllArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@AllArgsConstructor
public class AuthController {

    private final TokenService tokenService;

    private final AuthenticationManager authenticationManager;

    @CrossOrigin
    @PostMapping("/token")
    public TokenDTO token(@RequestBody LoginDTO loginDTO) {
        Authentication authentication = authenticationManager
                .authenticate(new UsernamePasswordAuthenticationToken(loginDTO.username(), loginDTO.password()));
        return tokenService.generateToken(authentication);
    }

}
