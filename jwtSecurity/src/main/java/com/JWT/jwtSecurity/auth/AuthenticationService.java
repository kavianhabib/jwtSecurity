package com.JWT.jwtSecurity.auth;

import com.JWT.jwtSecurity.JwtSecurityApplication;
import com.JWT.jwtSecurity.config.JwtService;
import com.JWT.jwtSecurity.user.Role;
import com.JWT.jwtSecurity.user.User;
import com.JWT.jwtSecurity.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthenticationService {
    private final UserRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    @Autowired
    public AuthenticationService(UserRepository userRepository, PasswordEncoder passwordEncoder,
                                 JwtService jwtService, AuthenticationManager authenticationManager){
        this.authenticationManager = authenticationManager;
        this.repository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
    }
    public AuthenticationResponse register(RegisterRequest request) {
        var user = User.builder()
                .setFirstName(request.getFirstName())
                .setLastName(request.getLastName())
                .setEmail(request.getEmail())
                .setPassword(passwordEncoder.encode(request.getPassword()))
                .setRole(Role.USER)
                .build();
        repository.save(user);

        var jwtToken = jwtService.generateToken(user);
        return AuthenticationResponse
                .builder()
                .setToken(jwtToken)
                .build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.getEmail(),
                            passwordEncoder.encode(request.getPassword())
                    )
            );
        }
        catch (Exception ex){
            System.out.println(ex);
        }


        // when we reach here it means that the user is properly authenticated
        var user = repository.findByEmail(request.getEmail()).orElseThrow();

        var jwtToken = jwtService.generateToken(user);
        return AuthenticationResponse
                .builder()
                .setToken(jwtToken)
                .build();
    }
}
