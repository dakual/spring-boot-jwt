package com.dakual.spring.repository;

import java.util.Optional;

import com.dakual.spring.models.ERole;
import com.dakual.spring.models.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
  Optional<Role> findByName(ERole name);
}
