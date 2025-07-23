package org.example.dz4_auth_service.repository;

import org.example.dz4_auth_service.DTO.EnumRole;
import org.example.dz4_auth_service.DTO.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Integer> {
    Optional<Role> findByName(EnumRole name);
}