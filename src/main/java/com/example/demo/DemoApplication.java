package com.example.demo;

import com.example.demo.model.IcesiPermission;
import com.example.demo.model.IcesiRole;
import com.example.demo.model.IcesiUser;
import com.example.demo.repository.PermissionRepository;
import com.example.demo.repository.RoleRepository;
import com.example.demo.repository.UserManagementRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.List;
import java.util.UUID;

@SpringBootApplication
public class DemoApplication {

	public static void main(String[] args) {
		SpringApplication.run(DemoApplication.class, args);
	}

	//@Bean
	CommandLineRunner commandLineRunner(UserManagementRepository users, RoleRepository roleRepository, PermissionRepository permissionRepository, PasswordEncoder encoder) {
		IcesiPermission icesiPermission = IcesiPermission.builder()
				.key("home")
				.path("/home")
				.build();
		IcesiPermission icesiPermission2 = IcesiPermission.builder()
				.key("admin")
				.path("/admin")
				.build();
		icesiPermission = permissionRepository.save(icesiPermission);
		icesiPermission2 = permissionRepository.save(icesiPermission2);
		IcesiRole icesiRole = IcesiRole.builder()
				.roleDescription("Role for demo")
				.roleName("ADMIN")
				.permissionList(List.of(icesiPermission, icesiPermission2))
				.build();
		IcesiRole icesiRole2 = IcesiRole.builder()
				.roleDescription("Role for demo")
				.roleName("USER")
				.permissionList(List.of(icesiPermission))
				.build();
		IcesiUser icesiUser = IcesiUser.builder()
				.icesiCode("A00324231")
				.age(22)
				.active(true)
				.address("av siempre viva 123")
				.email("johndoe@email.com")
				.role(icesiRole)
				.firstName("John")
				.lastName("Doe")
				.mobilePhone("+57123123123")
				.password(encoder.encode("password"))
				.build();
		IcesiUser icesiUser2 = IcesiUser.builder()
				.icesiCode("A00324231")
				.age(22)
				.active(true)
				.address("av siempre viva 123")
				.email("johndoe2@email.com")
				.role(icesiRole2)
				.firstName("John")
				.lastName("Doe")
				.mobilePhone("+57123123123")
				.password(encoder.encode("password"))
				.build();

		return args -> {
			users.save(icesiUser);
			users.save(icesiUser2);
		};
	}


}
