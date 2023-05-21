package com.example.demo.config;

import com.example.demo.model.SecurityUser;
import com.example.demo.security.CustomAuthentication;
import com.example.demo.service.UserManagementService;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Map;

@Component
public class IcesiAuthenticatorManager extends DaoAuthenticationProvider {



    public IcesiAuthenticatorManager(UserManagementService userManagementService,
                                     PasswordEncoder passwordEncoder) {
        this.setUserDetailsService(userManagementService);
        this.setPasswordEncoder(passwordEncoder);
    }


    @Override
    public Authentication createSuccessAuthentication(Object principal, Authentication authentication,
                                                      UserDetails user) {
        UsernamePasswordAuthenticationToken successAuthentication =
                (UsernamePasswordAuthenticationToken) super.createSuccessAuthentication(principal,
                        authentication, user);
        SecurityUser securityUser = (SecurityUser) user;
        return new CustomAuthentication(successAuthentication,
                securityUser.icesiUser().getIcesiUserId().toString());

    }


}
