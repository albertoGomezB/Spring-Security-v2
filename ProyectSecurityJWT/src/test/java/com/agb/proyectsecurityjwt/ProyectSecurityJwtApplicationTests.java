package com.agb.proyectsecurityjwt;

import com.agb.proyectsecurityjwt.entity.User;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.assertEquals;

@SpringBootTest
class ProyectSecurityJwtApplicationTests {

	@Test
	 void testDoSomething() {  // Noncompliant
		User user = new User();
		user.getUsername();

		assertEquals("admin", user.getUsername());
	}



}
