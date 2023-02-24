package com.example.demo.repository;

import com.example.demo.model.IcesiRole;
import org.springframework.data.repository.CrudRepository;

import java.util.UUID;

public interface RoleRepository extends CrudRepository<IcesiRole, UUID> {
}
