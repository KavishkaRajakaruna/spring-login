package com.example.demo;

import com.example.demo.domain.AppUser;
import com.example.demo.domain.Role;
import com.example.demo.service.AppUserService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;

@SpringBootApplication
public class DemoApplication {

	public static void main(String[] args) {
		SpringApplication.run(DemoApplication.class, args);
	}

	@Bean
	PasswordEncoder passwordEncoder(){
		return new BCryptPasswordEncoder();
	}

	@Bean
	CommandLineRunner commandLineRunner(AppUserService appUserService){
		return args -> {
			appUserService.saveRole(new Role(null,"ROLE_USER" ));
			appUserService.saveRole(new Role(null, "ROLE_MANAGER"));
			appUserService.saveRole(new Role(null, "ROLE_ADMIN"));
			appUserService.saveRole((new Role(null, "ROLE_SUPER_ADMIN")));

			appUserService.saveUser(new AppUser(null, "Kavishka Hirushan", "kavishka", "1234", new ArrayList<>()));
			appUserService.saveUser(new AppUser(null, "John Travota", "John", "1234", new ArrayList<>()));
			appUserService.saveUser(new AppUser(null, "Peter Pan", "peter", "1234", new ArrayList<>()));
			appUserService.saveUser(new AppUser(null, "Arsen Lupin", "lupin", "1234", new ArrayList<>()));

			appUserService.addRoleToUser("kavishka", "ROLE_USER");
			appUserService.addRoleToUser("john", "ROLE_MANAGER");
			appUserService.addRoleToUser("peter", "ROLE_SUPER_ADMIN");
			appUserService.addRoleToUser("peter", "ROLE_USER");
			appUserService.addRoleToUser("lupin", "ROLE_USER");
			appUserService.addRoleToUser("lupin", "ROLE_MANAGER");
			appUserService.addRoleToUser("lupin", "ROLE_SUPER_ADMIN");
		};
	}

}
