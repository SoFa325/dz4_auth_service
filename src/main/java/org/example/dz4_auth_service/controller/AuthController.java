package org.example.dz4_auth_service.controller;
import jakarta.validation.Valid;
import org.example.dz4_auth_service.DTO.EnumRole;
import org.example.dz4_auth_service.DTO.Role;
import org.example.dz4_auth_service.DTO.User;
import org.example.dz4_auth_service.DTO.UserDetailsImpl;
import org.example.dz4_auth_service.repository.RoleRepository;
import org.example.dz4_auth_service.repository.UserRepository;
import org.example.dz4_auth_service.requests.LoginRequest;
import org.example.dz4_auth_service.requests.SignUpRequest;
import org.example.dz4_auth_service.responses.JWTAuthentificationResponse;
import org.example.dz4_auth_service.utils.JWTUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;


@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JWTUtils jwtUtils;


    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtUtils.generateJwtToken(authentication);
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        List<String> roles = userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList());
        return ResponseEntity.ok(new JWTAuthentificationResponse(jwt,
                userDetails.getId(),
                userDetails.getUsername(),
                userDetails.getEmail(),
                roles));
    }

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignUpRequest signUpRequest) {

        if (userRepository.existsByUsername(signUpRequest.getUsername())) {
            return ResponseEntity
                    .badRequest()
                    .body("Error: Username is already taken!");
        }

        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            return ResponseEntity
                    .badRequest()
                    .body("Error: Email is already in use!");
        }

        User user = new User(
                signUpRequest.getUsername(),
                signUpRequest.getEmail(),
                passwordEncoder.encode(signUpRequest.getPassword())
        );

        Set<Role> roles = new HashSet<>();
        Role defaultRole = roleRepository.findByName(EnumRole.ROLE_GUEST)
                .orElseThrow(() -> new RuntimeException("Error: Role not found."));
        roles.add(defaultRole);

        if ("PREMIUM123".equals(signUpRequest.getRoleCode())) {
            Role premiumRole = roleRepository.findByName(EnumRole.ROLE_PREMIUM_USER)
                    .orElseThrow(() -> new RuntimeException("Error: Role not found."));
            roles.add(premiumRole);
        } else if ("ADMIN123".equals(signUpRequest.getRoleCode())) {
            Role adminRole = roleRepository.findByName(EnumRole.ROLE_ADMIN)
                    .orElseThrow(() -> new RuntimeException("Error: Role not found."));
            roles.add(adminRole);
        }

        user.setRoles(roles);
        userRepository.save(user);

        return ResponseEntity.ok("User registered successfully!");
    }


    @PostMapping("/refresh-token")
    public ResponseEntity<?> refreshToken(@RequestHeader("Authorization") String token) {
        String refreshedToken = jwtUtils.refreshToken(token.substring(7));
        return ResponseEntity.ok(new JWTAuthentificationResponse(refreshedToken, null, null, null, null));
    }

    @PostMapping("/signout")
    public ResponseEntity<?> logoutUser(@RequestHeader("Authorization") String token) {
        jwtUtils.invalidateToken(token.substring(7));
        return ResponseEntity.ok("Logout successful");
    }
}