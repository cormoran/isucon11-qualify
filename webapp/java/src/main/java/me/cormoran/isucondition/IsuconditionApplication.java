package me.cormoran.isucondition;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@SpringBootApplication
public class IsuconditionApplication {
	public static void main(String[] args) {
		SpringApplication.run(IsuconditionApplication.class, args);
	}

	@Bean
	ECPublicKey publicKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		String pem = Files.readString(Paths.get("../ec256-public.pem"))
				.replaceAll("-----.+?-----", "")
				.replaceAll("\\r?\\n", "")
				.trim();
		KeyFactory kf = KeyFactory.getInstance("EC");
		return (ECPublicKey) kf.generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(pem)));
	}

	@Bean
	JWTVerifier jwtVerifier(ECPublicKey publicKey) {
		return JWT.require(Algorithm.ECDSA256(publicKey)).build();
	}
}
