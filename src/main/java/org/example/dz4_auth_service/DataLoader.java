package org.example.dz4_auth_service;

import org.example.dz4_auth_service.DTO.EnumRole;
import org.example.dz4_auth_service.DTO.Role;
import org.example.dz4_auth_service.DTO.User;
import org.example.dz4_auth_service.repository.RoleRepository;
import org.example.dz4_auth_service.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.List;

@Component
public class DataLoader implements CommandLineRunner {

    @Autowired
    private UserRepository userRepository;
    @Autowired
    private RoleRepository roleRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) throws Exception {
        Role roleGuest = roleRepository.findByName(EnumRole.ROLE_GUEST)
                .orElseGet(() -> roleRepository.save(new Role(EnumRole.ROLE_GUEST)));
        Role rolePremium = roleRepository.findByName(EnumRole.ROLE_PREMIUM_USER)
                .orElseGet(() -> roleRepository.save(new Role(EnumRole.ROLE_PREMIUM_USER)));
        Role roleAdmin = roleRepository.findByName(EnumRole.ROLE_ADMIN)
                .orElseGet(() -> roleRepository.save(new Role(EnumRole.ROLE_ADMIN)));

        createUserIfNotExists("user1", "user1@example.com", "123456", List.of(roleGuest));
        createUserIfNotExists("premium_user", "premium@example.com", "123456", List.of(rolePremium));
        createUserIfNotExists("admin", "admin@example.com", "123456", List.of(roleAdmin));
    }

    private void createUserIfNotExists(String username, String email, String password, List<Role> roles) {
        if (!userRepository.existsByUsername(username)) {
            User user = new User(username, email, passwordEncoder.encode(password));
            user.setRoles(new HashSet<>(roles));
            userRepository.save(user);
        }
    }
}