package org.example.dz4_auth_service;

import org.example.dz4_auth_service.DTO.EnumRole;
import org.example.dz4_auth_service.DTO.Role;
import org.example.dz4_auth_service.repository.RoleRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

@Component
public class DataLoader implements CommandLineRunner {

    private final RoleRepository roleRepository;

    public DataLoader(RoleRepository roleRepository) {
        this.roleRepository = roleRepository;
    }

    @Override
    public void run(String... args) throws Exception {
        if (roleRepository.count() == 0) {
            roleRepository.save(new Role(EnumRole.ROLE_GUEST));
            roleRepository.save(new Role(EnumRole.ROLE_PREMIUM_USER));
            roleRepository.save(new Role(EnumRole.ROLE_ADMIN));

            System.out.println("Initial roles created");
        }
    }
}