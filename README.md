# TLSSocketFactory
TLSSocketFacory is TLS1.2 (HTTPS connection) capable with Java6 powered by BouncyCastle

## How to use
HttpsURLConnection.setDefaultSSLSocketFactory(new TLSSocketFactory());

## BouncyCastle maven repository
		<!-- https://mvnrepository.com/artifact/org.bouncycastle/bcprov-debug-jdk15on -->
		<dependency>
			<groupId>org.bouncycastle</groupId>
			<artifactId>bcprov-debug-jdk15on</artifactId>
			<version>1.55</version>
		</dependency>
		<!-- https://mvnrepository.com/artifact/org.bouncycastle/bcpkix-jdk15on -->
		<dependency>
			<groupId>org.bouncycastle</groupId>
			<artifactId>bcpkix-jdk15on</artifactId>
			<version>1.55</version>
		</dependency>
