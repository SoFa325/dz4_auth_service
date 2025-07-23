package org.example.dz4_auth_service.controller;

import org.example.dz4_auth_service.DTO.EnumRole;
import org.example.dz4_auth_service.DTO.Role;
import org.example.dz4_auth_service.DTO.User;
import org.example.dz4_auth_service.repository.UserRepository;
import org.example.dz4_auth_service.utils.JWTUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;

import java.util.HashSet;
import java.util.Set;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;


@SpringBootTest
@AutoConfigureMockMvc
class ExampleControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JWTUtils jwtUtils;

    private String adminToken;
    private String premiumToken;
    private String guestToken;

    @BeforeEach
    void setUp() {
        userRepository.deleteAll();

        createTestUser("admin", "admin@example.com", "admin123", EnumRole.ROLE_ADMIN);
        createTestUser("premium", "premium@example.com", "premium123", EnumRole.ROLE_PREMIUM_USER);
        createTestUser("guest", "guest@example.com", "guest123", EnumRole.ROLE_GUEST);

        adminToken = generateToken("admin", "admin123");
        premiumToken = generateToken("premium", "premium123");
        guestToken = generateToken("guest", "guest123");
    }

    private void createTestUser(String username, String email, String password, EnumRole role) {
        User user = new User(username, email, passwordEncoder.encode(password));
        Set<Role> roles = new HashSet<>();
        roles.add(new Role(role));
        user.setRoles(roles);
        userRepository.save(user);
    }

    private String generateToken(String username, String password) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(username, password));
        return jwtUtils.generateJwtToken(authentication);
    }

    @Test
    void testAllAccess() throws Exception {
        mockMvc.perform(get("/api/test/all"))
                .andExpect(status().isOk())
                .andExpect(content().string("Public Content."));
    }

    @Test
    void testUserAccessWithGuest() throws Exception {
        mockMvc.perform(get("/api/test/user")
                        .header("Authorization", "Bearer " + guestToken))
                .andExpect(status().isOk())
                .andExpect(content().string("User Content."));
    }

    @Test
    void testPremiumAccessWithPremiumUser() throws Exception {
        mockMvc.perform(get("/api/test/premium")
                        .header("Authorization", "Bearer " + premiumToken))
                .andExpect(status().isOk())
                .andExpect(content().string("Premium User Board."));
    }

    @Test
    void testAdminAccessWithAdmin() throws Exception {
        mockMvc.perform(get("/api/test/admin")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(content().string("Admin Board."));
    }
}