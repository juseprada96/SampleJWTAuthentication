package com.example.demo.repository;

import com.example.demo.model.IcesiUser;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface UserManagementRepository extends JpaRepository<IcesiUser, UUID> {

    Optional<IcesiUser> findByEmail(String email);

}
