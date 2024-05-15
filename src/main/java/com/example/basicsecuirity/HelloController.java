package com.example.basicsecuirity;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;


@RestController
public class HelloController {
    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtService jwtService;

    @GetMapping("/hello")
    public String hello(){
        return "Hello World! ";
    }

    @GetMapping("/about")
    public String about(){
        return "Welcome User ";
    }

    @PostMapping("/login")
    public String login(@RequestBody User user){
        try{
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(user.getUserName(), user.getPassword()));
            if(authentication.isAuthenticated()){
                return jwtService.generateToken(user.getUserName()); // username passed for providing subject in payload.

            }
        }
        catch (Exception e){
            return "Invalid username or password";
        }

        return "User not logged in";
    }
}
