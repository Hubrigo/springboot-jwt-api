package com.hugo.springbootjwtapi.auth;

import com.hugo.springbootjwtapi.auth.dto.AuthResponse;
import com.hugo.springbootjwtapi.auth.dto.LoginRequest;
import com.hugo.springbootjwtapi.auth.dto.RegisterRequest;
import com.hugo.springbootjwtapi.security.Role;
import com.hugo.springbootjwtapi.user.User;
import com.hugo.springbootjwtapi.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public AuthResponse login(LoginRequest request) {
        User user = userRepository.findByEmail(request.getEmail().trim().toLowerCase())
                .orElseThrow(() -> new RuntimeException("Invalid credentials"));

        boolean ok = passwordEncoder.matches(request.getPassword(), user.getPassword());
        if (!ok) throw new RuntimeException("Invalid credentials");

        return new AuthResponse("Login OK");
    }

    public AuthResponse register(RegisterRequest request) {

        if (request.getEmail() == null || request.getEmail().isBlank()) {
            return new AuthResponse("Email is required");
        }
        if (request.getPassword() == null || request.getPassword().isBlank()) {
            return new AuthResponse("Password is required");
        }
        //Validar que no exista el email
        if (userRepository.existsByEmail(request.getEmail())) {
            return new AuthResponse("Email already exists");
        }


        User user = new User();
        user.setEmail(request.getEmail().trim().toLowerCase());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.getRoles().add(Role.USER);

        userRepository.save(user);

        return new AuthResponse("User registered successfully");
    }

}
